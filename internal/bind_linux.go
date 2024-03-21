//go:build linux
// +build linux

package internal

import (
	"net"
	"net/netip"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/lysShub/rsocket/internal/config"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// ListenLocal occupy local port and avoid system stack reply RST
func ListenLocal(laddr netip.AddrPort, usedPort bool) (*net.TCPListener, netip.AddrPort, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: laddr.Addr().AsSlice(), Port: int(laddr.Port())})
	if err != nil {
		if usedPort {
			if errors.Is(err, unix.EADDRINUSE) {
				return nil, laddr, nil
			}
		}
		return nil, netip.AddrPort{}, err
	} else if usedPort {
		return nil, netip.AddrPort{}, config.ErrNotUsedPort(laddr.Port())
	}

	raw, err := l.SyscallConn()
	if err != nil {
		l.Close()
		return nil, netip.AddrPort{}, err
	}
	var e error
	err = raw.Control(func(fd uintptr) {
		if rawIns, e1 := bpf.Assemble([]bpf.Instruction{
			bpf.RetConstant{Val: 0},
		}); e1 != nil {
			e = e1
			return
		} else {
			prog := &unix.SockFprog{
				Len:    uint16(len(rawIns)),
				Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
			}

			if e = unix.SetsockoptSockFprog(
				int(fd), unix.SOL_SOCKET,
				unix.SO_ATTACH_FILTER, prog,
			); e != nil {
				return
			}
		}
	})
	if e != nil {
		l.Close()
		return nil, netip.AddrPort{}, e
	} else if err != nil {
		l.Close()
		return nil, netip.AddrPort{}, err
	}

	addr := netip.MustParseAddrPort(l.Addr().String())
	return l, netip.AddrPortFrom(laddr.Addr(), addr.Port()), nil
}
