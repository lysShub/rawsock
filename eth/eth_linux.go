//go:build linux
// +build linux

package eth

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/lysShub/rsocket/helper"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// https://man7.org/linux/man-pages/man7/packet.7.html
type Conn struct {
	fd  *os.File
	raw syscall.RawConn

	networkEndianProto uint16
	ifi                *net.Interface
}

var _ net.Conn = (*Conn)(nil)

func Listen(network string, addr any) (*Conn, error) {
	proto, err := getproto(network)
	if err != nil {
		return nil, err
	}
	ifi, err := assertAddr(addr)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(helper.Htons(proto)))
	if err != nil {
		return nil, err
	}

	if err = unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: helper.Htons(proto),
		Ifindex:  ifi.Index,
		Pkttype:  unix.PACKET_HOST,
	}); err != nil {
		return nil, err
	}

	// for support dataline
	if err = unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "")
	raw, err := f.SyscallConn()
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &Conn{
		fd:                 f,
		raw:                raw,
		networkEndianProto: helper.Htons(proto),
		ifi:                ifi,
	}, nil
}

func assertAddr(addr any) (*net.Interface, error) {
	switch addr := addr.(type) {
	case string:
		return net.InterfaceByName(addr)
	case int:
		return net.InterfaceByIndex(addr)
	case net.HardwareAddr:
		ifs, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, e := range ifs {
			if string(e.HardwareAddr) == string(addr) {
				return &e, nil
			}
		}
		return nil, fmt.Errorf("invalid hardware address %s", addr.String())
	case *net.Interface:
		return addr, nil
	default:
		return nil, fmt.Errorf("invalid ethernet address %V", addr)
	}
}

func getproto(network string) (uint16, error) {
	var proto uint16
	switch network {
	case "eth:ip4":
		proto = unix.ETH_P_IP
	case "eth:ip6":
		proto = unix.ETH_P_IPV6
	case "eth", "eth:ip":
		proto = unix.ETH_P_ALL
	default:
		return 0, &net.OpError{
			Op: "socket", Net: "eth",
			Err: net.UnknownNetworkError(network),
		}
	}
	return proto, nil
}

func (c *Conn) Read(eth []byte) (n int, err error) {
	n, from, err := c.Recvfrom(eth[header.EthernetMinimumSize:], 0)
	if err != nil {
		return 0, err
	}

	header.Ethernet(eth).Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(from),
		DstAddr: tcpip.LinkAddress(c.ifi.HardwareAddr),
		Type:    tcpip.NetworkProtocolNumber(c.networkEndianProto),
	})
	return n + header.EthernetMinimumSize, nil
}

func (c *Conn) Recvfrom(ip []byte, flags int) (n int, from net.HardwareAddr, err error) {
	var src unix.Sockaddr
	var operr error
	if err = c.raw.Read(func(fd uintptr) (done bool) {
		n, src, operr = unix.Recvfrom(int(fd), ip, 0)
		return operr != syscall.EWOULDBLOCK
	}); err != nil {
		return 0, nil, err
	}
	if operr != nil {
		return 0, nil, operr
	}

	if src, ok := src.(*unix.SockaddrLinklayer); ok {
		from = src.Addr[:src.Halen]
	}
	return n, from, nil
}

func (c *Conn) Write(eth []byte) (n int, err error) {
	to := net.HardwareAddr(header.Ethernet(eth).DestinationAddress())
	err = c.WriteTo(eth[header.EthernetMinimumSize:], 0, to)
	if err != nil {
		return 0, err
	}
	return len(eth), nil
}

func (c *Conn) WriteTo(ip []byte, flags int, to net.HardwareAddr) (err error) {
	dst := &unix.SockaddrLinklayer{
		Protocol: c.networkEndianProto,
		Ifindex:  c.ifi.Index,
		Pkttype:  unix.PACKET_HOST,
		Halen:    uint8(len(to)),
	}
	copy(dst.Addr[:], to)

	var operr error
	if err = c.raw.Write(func(fd uintptr) (done bool) {
		operr = unix.Sendto(int(fd), ip, flags, dst)
		return true
	}); err != nil {
		return err
	}
	if operr != nil {
		return err
	}

	return nil
}

func (c *Conn) Close() error                       { return c.fd.Close() }
func (c *Conn) LocalAddr() net.Addr                { return ETHAddr(c.ifi.HardwareAddr) }
func (c *Conn) RemoteAddr() net.Addr               { return nil }
func (c *Conn) SyscallConn() syscall.RawConn       { return c.raw }
func (c *Conn) SetDeadline(t time.Time) error      { return c.fd.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.fd.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

type ETHAddr net.HardwareAddr

func (e ETHAddr) Network() string { return "eth" }
func (e ETHAddr) String() string  { return net.HardwareAddr(e).String() }
