package raw

import (
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type rawTcpWithBpf struct {
	laddr, raddr *net.TCPAddr
	tcp          *net.TCPListener

	raw *net.IPConn
}

func NewRawTCP(laddr, raddr *net.TCPAddr) (*rawTcpWithBpf, error) {
	var r = &rawTcpWithBpf{raddr: raddr}
	if laddr == nil {
		laddr = &net.TCPAddr{}
	}

	var err error
	if r.raddr == nil {
		r.raw, err = net.ListenIP("ip:tcp",
			&net.IPAddr{IP: laddr.IP, Zone: laddr.Zone},
		)
	} else {
		r.raw, err = net.DialIP("ip:tcp",
			&net.IPAddr{IP: laddr.IP, Zone: laddr.Zone},
			&net.IPAddr{IP: raddr.IP, Zone: raddr.Zone},
		)
	}
	if err != nil {
		return nil, err
	} else {
		loc := r.raw.LocalAddr().(*net.IPAddr)
		r.laddr = &net.TCPAddr{IP: loc.IP, Port: laddr.Port, Zone: loc.Zone}
	}

	// bindLocal, forbid other process use this port and avoid RST by system-stack
	r.tcp, err = net.ListenTCP("tcp", r.laddr)
	if err != nil {
		r.raw.Close()
		return nil, err
	}

	if err = r.setBpf(); err != nil {
		r.raw.Close()
		r.tcp.Close()
		return nil, err
	}

	return r, nil
}

func (l *rawTcpWithBpf) setBpf() error {
	if err := l.setRawBpf(); err != nil {
		return err
	}
	return l.setTcpBpf()
}

func (l *rawTcpWithBpf) setRawBpf() error {
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
	if l.raddr != nil {
		ins = append(ins, []bpf.Instruction{
			// source port
			bpf.LoadIndirect{Off: 0, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(l.raddr.Port), SkipTrue: 1},
			bpf.RetConstant{Val: 0},
		}...)
	}
	// destination port
	ins = append(ins, []bpf.Instruction{
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(l.laddr.Port), SkipTrue: 1},
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

func (l *rawTcpWithBpf) setTcpBpf() error {
	rawIns, err := bpf.Assemble([]bpf.Instruction{
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		return err
	}
	prog := &unix.SockFprog{
		Len:    uint16(len(rawIns)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
	}
	s, err := l.tcp.SyscallConn()
	if err != nil {
		return err
	}
	var e error
	err = s.Control(func(fd uintptr) {
		e = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
	})
	if e != nil {
		return err
	}
	return err
}

func (r *rawTcpWithBpf) Read(b []byte) (n int, err error) {
	return r.raw.Read(b)
}
func (r *rawTcpWithBpf) Write(b []byte) (n int, err error) {
	return r.raw.Write(b)
}
func (r *rawTcpWithBpf) WriteTo(b []byte, ip *net.IPAddr) (n int, err error) {
	return r.raw.WriteToIP(b, ip)
}
func (r *rawTcpWithBpf) Close() error {
	var err error
	if e := r.raw.Close(); err != nil {
		err = e
	}
	if e := r.tcp.Close(); err != nil {
		err = e
	}
	return err
}
func (r *rawTcpWithBpf) LocalAddr() net.Addr  { return r.laddr }
func (r *rawTcpWithBpf) RemoteAddr() net.Addr { return r.raddr }
func (r *rawTcpWithBpf) SetDeadline(t time.Time) error {
	return r.raw.SetDeadline(t)
}
func (r *rawTcpWithBpf) SetReadDeadline(t time.Time) error {
	return r.raw.SetReadDeadline(t)
}
func (r *rawTcpWithBpf) SetWriteDeadline(t time.Time) error {
	return r.raw.SetWriteDeadline(t)
}
func (r *rawTcpWithBpf) SyscallConn() (syscall.RawConn, error) {
	return r.raw.SyscallConn()
}
