//go:build linux
// +build linux

package conn

import (
	"net"
	"net/netip"
	"unsafe"

	"github.com/lysShub/sockit/helper"
	"github.com/lysShub/sockit/route"
	"github.com/pkg/errors"

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
		return nil, netip.AddrPort{}, errors.WithStack(ErrNotUsedPort(laddr.Port()))
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

func SetTSOByAddr(addr netip.Addr, tso bool) error {
	table, err := route.GetTable()
	if err != nil {
		return err
	}

	for _, e := range table {
		if e.Addr == addr {
			name, err := helper.IoctlGifname(int(e.Interface))
			if err != nil {
				return err
			}
			return helper.IoctlTSO(name, tso)
		}
	}
	return nil
}
