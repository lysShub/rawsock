//go:build windows
// +build windows

package tcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/relraw"
	"golang.org/x/sys/windows"
)

type rawTCPWithDivert struct {
	laddr, raddr *net.TCPAddr
	tcp          windows.Handle

	raw *divert.Divert

	outAddr *divert.Address
}

var _ relraw.Raw = (*rawTCPWithDivert)(nil)

// NewRawWithDivert with divert https://github.com/basil00/Divert
func NewRawWithDivert(localAddress, remoteAddres *net.TCPAddr, dll *divert.DivertDLL) (*rawTCPWithDivert, error) {
	var r = &rawTCPWithDivert{
		raddr:   remoteAddres,
		outAddr: &divert.Address{Layer: divert.LAYER_NETWORK, Event: divert.NETWORK_PACKET},
	}
	var err error
	r.outAddr.SetOutbound(true)

	// bindLocal, forbid other process use this port
	r.tcp, r.laddr, err = bindLocal(localAddress)
	if err != nil {
		r.Close()
		return nil, err
	}

	var filter string
	// ref: https://reqrypt.org/windivert-doc.html#divert_open
	// note that Windows considers any packet originating from, and destined to, the current machine to be a
	// loopback packet, so loopback packets are not limited to localhost addresses. Note that WinDivert considers
	// loopback packets to be outbound only, and will not capture loopback packets on the inbound path.
	if r.raddr == nil {
		if r.laddr.IP.IsLoopback() {
			// 127.x.x.x only recv loopback packet
			filter = fmt.Sprintf(
				"tcp and remotePort=%d and remoteAddr=%s",
				r.laddr.Port, r.laddr.String(),
			)
		} else {
			filter = fmt.Sprintf(
				"(!loopback and tcp and localPort=%d and localAddr=%s) or (loopback and tcp and remotePort=%d and remoteAddr=%s)",
				r.laddr.Port, r.laddr.String(),
				r.laddr.Port, r.laddr.String(),
			)
		}
	} else {
		if isWindowsLoopback(r.laddr.IP) && isWindowsLoopback(r.raddr.IP) {
			filter = fmt.Sprintf(
				"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
				r.raddr.Port, r.raddr.IP.String(), r.laddr.Port, r.laddr.IP.String(),
			)
		} else {
			filter = fmt.Sprintf(
				"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
				r.raddr.Port, r.raddr.IP.String(), r.laddr.Port, r.laddr.IP.String(),
			)
		}
	}
	if r.raw, err = dll.Open(filter, divert.LAYER_NETWORK, 0, 0); err != nil {
		r.Close()
		return nil, err
	}

	return r, nil
}

func bindLocal(laddr *net.TCPAddr) (windows.Handle, *net.TCPAddr, error) {
	var sa windows.Sockaddr = &windows.SockaddrInet4{}
	var af int = windows.AF_INET
	if laddr != nil {
		if len(laddr.IP) > 0 {
			nip, ok := netip.AddrFromSlice(laddr.IP)
			if !ok {
				return windows.InvalidHandle, nil, &net.OpError{
					Op:  "bind",
					Net: laddr.Network(),
					Err: fmt.Errorf("invalid sockaddr %s", laddr),
				}
			}
			if nip.Is4() {
				sa = &windows.SockaddrInet4{Addr: nip.As4(), Port: laddr.Port}
			} else {
				sa = &windows.SockaddrInet6{Addr: nip.As16(), Port: laddr.Port}
				af = windows.AF_INET6
			}
		} else {
			sa = &windows.SockaddrInet4{Port: laddr.Port}
		}
	}

	fd, err := windows.Socket(af, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return windows.InvalidHandle, nil, &net.OpError{
			Op:  "socket",
			Err: err,
		}
	}

	if err := windows.Bind(fd, sa); err != nil {
		return windows.InvalidHandle, nil, &net.OpError{
			Op:  "bind",
			Err: err,
		}
	}

	rsa, err := windows.Getsockname(fd)
	if err != nil {
		return windows.InvalidHandle, nil, &net.OpError{
			Op:  "getsockname",
			Err: err,
		}
	}
	switch sa := rsa.(type) {
	case *windows.SockaddrInet4:
		return fd, &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: sa.Port,
		}, nil
	case *windows.SockaddrInet6:
		return fd, &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: sa.Port,
			Zone: "", // todo
		}, nil
	default:
		panic("impossible")
	}
}

func isWindowsLoopback(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	} else if ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6zero) {
		return true
	}

	ifs, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch a := addr.(type) {
			case *net.IPAddr:
				if a.IP.Equal(ip) {
					return true
				}
			case *net.IPNet:
				if a.Contains(ip) {
					return true
				}
			default:
			}
		}
	}
	return false
}

func (r *rawTCPWithDivert) Close() error {
	var errs []error

	if r.raw != nil {
		errs = append(errs, r.raw.Close())
	}
	if r.tcp != 0 {
		errs = append(errs, r.raw.Close())
	}
	return errors.Join(errs...)
}
func (r *rawTCPWithDivert) LocalAddr() net.Addr  { return r.laddr }
func (r *rawTCPWithDivert) RemoteAddr() net.Addr { return r.raddr }
func (r *rawTCPWithDivert) Read(b []byte) (n int, err error) {
	n, _, err = r.raw.Recv(b)
	return n, err
}
func (r *rawTCPWithDivert) Write(b []byte) (n int, err error) {
	return r.raw.Send(b, r.outAddr)
}

func (r *rawTCPWithDivert) SetDeadline(t time.Time) error {
	return nil
}
func (r *rawTCPWithDivert) SetReadDeadline(t time.Time) error {
	return nil
}
func (r *rawTCPWithDivert) SetWriteDeadline(t time.Time) error {
	return nil
}
func (r *rawTCPWithDivert) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}
