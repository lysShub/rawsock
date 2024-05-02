//go:build windows
// +build windows

package rawsock

import (
	"net"
	"net/netip"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// BindLocal, occupy local tcp port, 1. alloc useable port for default-port, 2. avoid other process
// use this port, 3. system tcp stack don't send RST automatically for this port request
func BindLocal(proto tcpip.TransportProtocolNumber, laddr netip.AddrPort, usedPort bool) (windows.Handle, netip.AddrPort, error) {
	var (
		sa windows.Sockaddr
		af int = windows.AF_INET
		st int = windows.SOCK_STREAM
		po int = windows.IPPROTO_TCP
	)

	if laddr.Addr().Is4() {
		sa = &windows.SockaddrInet4{Addr: laddr.Addr().As4(), Port: int(laddr.Port())}
	} else {
		sa = &windows.SockaddrInet6{Addr: laddr.Addr().As16(), Port: int(laddr.Port())}
		af = windows.AF_INET6
	}
	switch proto {
	case header.TCPProtocolNumber:
	case header.UDPProtocolNumber:
		st = windows.SOCK_DGRAM
		po = windows.IPPROTO_UDP
	default:
		return 0, netip.AddrPort{}, errors.Errorf("not support protocol %d", proto)
	}

	fd, err := windows.Socket(af, st, po)
	if err != nil {
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "socket",
			Err: err,
		}
	}

	if err := windows.Bind(fd, sa); err != nil {
		if err == windows.WSAEADDRINUSE && usedPort {
			return 0, laddr, nil
		}
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "bind",
			Err: err,
		}
	} else if usedPort {
		return windows.InvalidHandle, netip.AddrPort{}, errors.WithStack(ErrNotUsedPort(laddr.Port()))
	}

	if laddr.Port() == 0 {
		rsa, err := windows.Getsockname(fd)
		if err != nil {
			return windows.InvalidHandle, netip.AddrPort{}, errors.WithMessage(err, "getsockname")
		}
		switch sa := rsa.(type) {
		case *windows.SockaddrInet4:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		case *windows.SockaddrInet6:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		default:
		}
	}
	return fd, laddr, nil
}
