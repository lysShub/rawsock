package unix

import (
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/lysShub/rsocket"
	"github.com/lysShub/rsocket/test/debug"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// https://man7.org/linux/man-pages/man7/packet.7.html
// NOTICE: can't work on tun device
type ETHConn struct {
	fd  *os.File
	raw syscall.RawConn

	proto uint16
	ifi   *net.Interface
}

var _ net.Conn = (*ETHConn)(nil)

func NewETH(network string, addr net.HardwareAddr) (*ETHConn, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var i *net.Interface
	for _, e := range ifs {
		if string(e.HardwareAddr) == string(addr) {
			i = &e
			break
		}
	}
	if i == nil {
		return nil, errors.Errorf("invalid hardware address %s", addr.String())
	}
	return newETHConn(network, i)
}

func NewETHName(network, name string) (*ETHConn, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return newETHConn(network, i)
}

func NewETHIdx(network string, ifidx int) (*ETHConn, error) {
	ifi, err := net.InterfaceByIndex(ifidx)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return newETHConn(network, ifi)
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
		return 0, errors.WithStack(&net.OpError{
			Op: "socket", Net: "eth",
			Err: net.UnknownNetworkError(network),
		})
	}
	return proto, nil
}

func newETHConn(network string, ifi *net.Interface) (*ETHConn, error) {
	proto, err := getproto(network)
	if err != nil {
		return nil, err
	}
	if debug.Debug() {
		hw, err := rsocket.HardwareAddr(ifi.Name)
		if err != nil {
			return nil, err
		} else if string(hw) == string(make([]byte, 6)) {
			// such as tun device
			return nil, errors.Errorf("not support device %s without ethernet layer", ifi.Name)
		}
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(proto)))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err = unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(proto),
		Ifindex:  ifi.Index,
		Pkttype:  unix.PACKET_HOST,
	}); err != nil {
		return nil, err
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return nil, errors.WithStack(err)
	}

	f := os.NewFile(uintptr(fd), "")
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("invalid file descriptor")
	}

	raw, err := f.SyscallConn()
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &ETHConn{
		fd:    f,
		raw:   raw,
		proto: proto,
		ifi:   ifi,
	}, nil
}

func htons(b uint16) uint16 {
	return binary.BigEndian.Uint16(
		binary.NativeEndian.AppendUint16(nil, b),
	)
}

func (c *ETHConn) Read(ip []byte) (int, error) {
	n, err := c.fd.Read(ip)
	return n, err
}

func (c *ETHConn) Write(eth []byte) (int, error) {
	// todo: valid loopback packet, not suppert

	n, err := c.fd.Write(eth)
	return n, err
}

func (c *ETHConn) Close() error {
	return c.fd.Close()
}

func (c *ETHConn) LocalAddr() net.Addr {
	return ETHAddr(c.ifi.HardwareAddr)
}

func (c *ETHConn) RemoteAddr() net.Addr {
	return nil
}

func (c *ETHConn) SyscallConn() syscall.RawConn       { return c.raw }
func (c *ETHConn) SetDeadline(t time.Time) error      { return c.fd.SetDeadline(t) }
func (c *ETHConn) SetReadDeadline(t time.Time) error  { return c.fd.SetReadDeadline(t) }
func (c *ETHConn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

type ETHAddr net.HardwareAddr

func (e ETHAddr) Network() string { return "eth" }
func (e ETHAddr) String() string  { return net.HardwareAddr(e).String() }
