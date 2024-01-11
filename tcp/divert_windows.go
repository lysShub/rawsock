//go:build windows
// +build windows

package tcp

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/lysShub/go-divert"
	"golang.org/x/sys/windows"
)

type rawTCPWithDivert struct {
	laddr, raddr *net.TCPAddr
	tcp          windows.Handle

	raw *divert.Divert
}

// NewRawWithDivert with divert https://github.com/basil00/Divert
func NewRawWithDivert(laddr, raddr *net.TCPAddr, dll *divert.DivertDLL) (*rawTCPWithDivert, error) {
	var r = &rawTCPWithDivert{raddr: raddr}
	var err error

	// bindLocal, forbid other process use this port
	r.tcp, r.laddr, err = bindLocal(laddr)
	if err != nil {
		return nil, err
	}

	var filter string
	if r.raddr == nil {
		filter = fmt.Sprintf(
			"inbound and tcp and localPort=%d and localAddr=%s",
			r.laddr.Port, r.laddr.String(),
		)
	} else {
		filter = fmt.Sprintf(
			"inbound and tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			r.laddr.Port, r.laddr.IP.String(), r.raddr.Port, r.raddr.IP.String(),
		)
	}
	if r.raw, err = dll.Open(filter, divert.LAYER_NETWORK, 0, 0); err != nil {
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

func (r *rawTCPWithDivert) Close() error         { return r.raw.Close() }
func (r *rawTCPWithDivert) LocalAddr() net.Addr  { return r.laddr }
func (r *rawTCPWithDivert) RemoteAddr() net.Addr { return r.raddr }
func (r *rawTCPWithDivert) Read(b []byte) (n int, err error) {
	n, _, err = r.raw.Recv(b)
	return n, err
}
func (r *rawTCPWithDivert) Write(b []byte) (n int, err error) {
	return r.raw.Send(b, &divert.Address{})
}
func (r *rawTCPWithDivert) WriteTo(b []byte, ip *net.IPAddr) (n int, err error) {
	return r.raw.Send(b, &divert.Address{})
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
