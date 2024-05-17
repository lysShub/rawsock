//go:build linux
// +build linux

package bind

import (
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"unsafe"

	"github.com/lysShub/netkit/route"
	netcall "github.com/lysShub/netkit/syscall"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// ListenLocal occupy local tcp port, 1. alloc useable port for default-port, 2. avoid other process
// use this port, 3. system tcp stack don't send RST automatically for this port request
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

// BindLocal, occupy local tcp port, 1. alloc useable port for default-port, 2. avoid other process
// use this port
func BindLocal(proto tcpip.TransportProtocolNumber, laddr netip.AddrPort, usedPort bool) (int, netip.AddrPort, error) {
	var (
		sa unix.Sockaddr
		af int = unix.AF_INET
		st int = unix.SOCK_STREAM
		po int = unix.IPPROTO_TCP
	)
	if laddr.Addr().Is4() {
		sa = &unix.SockaddrInet4{Addr: laddr.Addr().As4(), Port: int(laddr.Port())}
	} else {
		sa = &unix.SockaddrInet6{Addr: laddr.Addr().As16(), Port: int(laddr.Port())}
		af = unix.AF_INET6
	}
	switch proto {
	case header.TCPProtocolNumber:
	case header.UDPProtocolNumber:
		st = unix.SOCK_DGRAM
		po = unix.IPPROTO_UDP
	default:
		return 0, netip.AddrPort{}, errors.Errorf("not support protocol %d", proto)
	}

	fd, err := unix.Socket(af, st, po)
	if err != nil {
		return 0, netip.AddrPort{}, &net.OpError{
			Op:  "socket",
			Err: err,
		}
	}

	if err := unix.Bind(fd, sa); err != nil {
		if err == unix.EADDRINUSE && usedPort {
			return 0, laddr, nil
		}
		return 0, netip.AddrPort{}, &net.OpError{
			Op:  "bind",
			Err: err,
		}
	} else if usedPort {
		return 0, netip.AddrPort{}, errors.WithStack(ErrNotUsedPort(laddr.Port()))
	}

	if laddr.Port() == 0 {
		rsa, err := unix.Getsockname(fd)
		if err != nil {
			return 0, netip.AddrPort{}, errors.WithMessage(err, "getsockname")
		}
		switch sa := rsa.(type) {
		case *unix.SockaddrInet4:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		case *unix.SockaddrInet6:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		default:
		}
	}
	return fd, laddr, nil
}

var ethOffloadCache = struct {
	sync.RWMutex
	GRO map[netip.Addr]bool
}{
	GRO: map[netip.Addr]bool{},
}

// todo: 还有 generic-segmentation-offload, large-receive-offload
func SetGRO(local, remote netip.Addr, gro bool) error {
	// get route table is expensive call, cache it.
	if !remote.IsPrivate() {
		ethOffloadCache.RLock()
		old, has := ethOffloadCache.GRO[local]
		ethOffloadCache.RUnlock()

		if has && old == gro {
			return nil
		} else {
			defer func() {
				ethOffloadCache.Lock()
				ethOffloadCache.GRO[local] = gro
				ethOffloadCache.Unlock()
			}()
		}
	}

	table, err := route.GetTable()
	if err != nil {
		return err
	}

	var ifIdx uint32
	if remote.IsPrivate() {
		for _, e := range table {
			if e.Addr.IsLoopback() {
				ifIdx = e.Interface
				break
			}
		}
	} else {
		for _, e := range table {
			if e.Addr == local {
				ifIdx = e.Interface
				break
			}
		}
	}
	if ifIdx == 0 {
		return errors.Errorf("invalid local address %s", local.String())
	}

	name, err := netcall.IoctlGifname(int(ifIdx))
	if err != nil {
		return err
	}
	if err := netcall.IoctlGRO(name, gro); err != nil {
		return err
	}

	// todo: support rx-gro-hw
	// ethtool --offload eth0 rx-gro-hw off
	cmd := exec.Command("ethtool", "--offload", name, "rx-gro-hw", "off")
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) > 0 {
		return errors.Errorf(`exec "%s", error: %s, message: %s`, cmd.String(), err, string(out))
	}

	return nil
}
