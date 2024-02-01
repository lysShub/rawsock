//go:build linux
// +build linux

package bpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/tcp"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listenerBPF struct {
	laddr netip.AddrPort

	tcp *net.TCPListener

	raw *net.IPConn

	conns   map[netip.AddrPort]struct{}
	connsMu sync.RWMutex

	readb []byte
}

func Listen(laddr netip.AddrPort) (*listenerBPF, error) {
	var l = &listenerBPF{
		conns: make(map[netip.AddrPort]struct{}, 16),
		readb: make([]byte, header.IPv6MinimumSize+header.TCPHeaderMaximumSize),
	}

	var err error
	l.tcp, l.laddr, err = listenLocal(laddr)
	if err != nil {
		l.Close()
		return nil, err
	}

	l.raw, err = net.ListenIP(
		"ip:tcp",
		&net.IPAddr{IP: l.laddr.Addr().AsSlice(), Zone: laddr.Addr().Zone()},
	)
	if err != nil {
		l.Close()
		return nil, err
	}

	if err := l.setSynFilterBPF(); err != nil {
		l.Close()
		return nil, err
	}

	return l, nil
}

func (l *listenerBPF) setSynFilterBPF() error {
	var ins = []bpf.Instruction{
		// load ip version
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},

		// ipv4
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 4, SkipTrue: 1},
		bpf.LoadMemShift{Off: 0},

		// ipv6
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 1},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 40},
	}

	ins = append(ins, []bpf.Instruction{
		// destination port
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(l.laddr.Port()), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// SYN flag
		bpf.LoadIndirect{Off: 13, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0b01000000},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0b01000000, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		bpf.RetConstant{Val: 0xffff},
	}...)

	var prog *unix.SockFprog
	if rawIns, err := bpf.Assemble(ins); err != nil {
		return err
	} else {
		prog = &unix.SockFprog{
			Len:    uint16(len(rawIns)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
		}
	}

	raw, err := l.raw.SyscallConn()
	if err != nil {
		return err
	}
	e := raw.Control(func(fd uintptr) {
		err = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
	})
	if err != nil {
		return err
	} else if e != nil {
		return e
	}
	return nil
}

// todo: not support private proto that not start with tcp SYN flag
func (l *listenerBPF) Accept() (relraw.RawConn, error) {
	for {
		n, err := l.raw.Read(l.readb)
		if err != nil {
			return nil, err
		} else if n == 0 {
			continue
		}

		var raddr netip.AddrPort
		switch header.IPVersion(l.readb) {
		case 4:
			iphdr := header.IPv4(l.readb[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
		case 6:
			iphdr := header.IPv6(l.readb[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
		default:
			continue
		}

		l.connsMu.RLock()
		_, ok := l.conns[raddr]
		l.connsMu.RUnlock()

		if !ok {
			c := &connBPF{
				laddr:   l.laddr,
				raddr:   raddr,
				closeFn: l.deleteConn,
			}
			return c, c.init()
		}
	}
}

func (l *listenerBPF) deleteConn(raddr netip.AddrPort) error {
	if l == nil {
		return nil
	}
	l.connsMu.Lock()
	delete(l.conns, raddr)
	l.connsMu.Unlock()
	return nil
}

func (l *listenerBPF) Close() error {
	var errs []error
	if l.tcp != nil {
		errs = append(errs, l.tcp.Close())
	}
	if l.raw != nil {
		errs = append(errs, l.raw.Close())
	}
	return errors.Join(errs...)
}

type connBPF struct {
	laddr, raddr netip.AddrPort
	tcp          *net.TCPListener

	raw *net.IPConn

	closeFn tcp.CloseCallback
}

var _ relraw.RawConn = (*connBPF)(nil)

func Connect(laddr, raddr netip.AddrPort) (*connBPF, error) {
	var r = &connBPF{raddr: raddr}
	var err error

	r.tcp, r.laddr, err = listenLocal(laddr)
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}

	// if !internal.ValideConnectAddrs(r.laddr.Addr(), r.raddr.Addr()) {
	// 	r.Close()
	// 	return nil, &net.OpError{
	// 		Op:     "listen",
	// 		Source: r.LocalAddr(),
	// 		Addr:   r.RemoteAddr(),
	// 		Err:    fmt.Errorf("invalid address"),
	// 	}
	// }

	return r, r.init()
}

func (r *connBPF) init() (err error) {
	r.raw, err = net.DialIP(
		"ip:tcp",
		&net.IPAddr{IP: r.laddr.Addr().AsSlice(), Zone: r.laddr.Addr().Zone()},
		&net.IPAddr{IP: r.raddr.Addr().AsSlice(), Zone: r.raddr.Addr().Zone()},
	)
	if err != nil {
		return errors.Join(err, r.Close())
	}

	if sc, err := r.raw.SyscallConn(); err != nil {
		return errors.Join(err, r.Close())
	} else {
		e := sc.Control(func(fd uintptr) {
			// read with ip header
			err = unix.SetsockoptByte(int(fd), unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
			if err != nil {
				return
			}
			err = setPortsFilterBPF(0, r.laddr.Port(), r.raddr.Port())
			if err != nil {
				return
			}
		})
		if err := errors.Join(err, e); err != nil {
			return errors.Join(err, r.Close())
		}
	}

	return nil
}

// setPortsFilterBPF BPF filter by localPort and remotePort
func setPortsFilterBPF(fd uintptr, localPort, remotePort uint16) error {
	var ins = []bpf.Instruction{
		// load ip version
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},

		// ipv4
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 4, SkipTrue: 1},
		bpf.LoadMemShift{Off: 0},

		// ipv6
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 1},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 40},
	}

	ins = append(ins, []bpf.Instruction{
		// source port
		bpf.LoadIndirect{Off: 0, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(remotePort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// destination port
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(localPort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		bpf.RetConstant{Val: 0xffff},
	}...)

	var prog *unix.SockFprog
	if rawIns, err := bpf.Assemble(ins); err != nil {
		return err
	} else {
		prog = &unix.SockFprog{
			Len:    uint16(len(rawIns)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
		}
	}

	return unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
}

// listenLocal occupy local port and avoid system stack send RST
func listenLocal(laddr netip.AddrPort) (*net.TCPListener, netip.AddrPort, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: laddr.Addr().AsSlice(), Port: int(laddr.Port())})
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	raw, err := l.SyscallConn()
	if err != nil {
		return nil, netip.AddrPort{}, errors.Join(err, l.Close())
	}
	var e error
	err = raw.Control(func(fd uintptr) {
		rawIns, e1 := bpf.Assemble([]bpf.Instruction{
			bpf.RetConstant{Val: 0},
		})
		if e1 != nil {
			e = e1
			return
		}
		prog := &unix.SockFprog{
			Len:    uint16(len(rawIns)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
		}

		e = unix.SetsockoptSockFprog(
			int(fd), unix.SOL_SOCKET,
			unix.SO_ATTACH_FILTER, prog,
		)
	})
	if err := errors.Join(err, e); err != nil {
		return nil, netip.AddrPort{}, errors.Join(e, l.Close())
	}

	addr := netip.MustParseAddrPort(l.Addr().String())
	return l, netip.AddrPortFrom(laddr.Addr(), addr.Port()), nil
}

func (r *connBPF) Read(b []byte) (n int, err error) {
	return r.raw.Read(b)
}
func (r *connBPF) Write(b []byte) (n int, err error) {
	return r.raw.Write(b)
}

func (r *connBPF) WriteReservedIPHeader(ip []byte, reserved int) (err error) {
	return
}

func (r *connBPF) Inject(b []byte) (err error) {
	return
}
func (r *connBPF) InjectReservedIPHeader(ip []byte, reserved int) (err error) {
	return
}

func (r *connBPF) Close() error {
	var errs []error
	if r.closeFn != nil {
		errs = append(errs, r.closeFn(r.raddr))
	}
	if r.tcp != nil {
		errs = append(errs, r.tcp.Close())
	}
	if r.raw != nil {
		errs = append(errs, r.raw.Close())
	}
	return errors.Join(errs...)
}

func (r *connBPF) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   r.laddr.Addr().AsSlice(),
		Port: int(r.laddr.Port()),
		Zone: r.laddr.Addr().Zone(),
	}
}
func (r *connBPF) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   r.raddr.Addr().AsSlice(),
		Port: int(r.raddr.Port()),
		Zone: r.raddr.Addr().Zone(),
	}
}
func (r *connBPF) LocalAddrAddrPort() netip.AddrPort {
	return r.laddr
}
func (r *connBPF) RemoteAddrAddrPort() netip.AddrPort {
	return r.raddr
}