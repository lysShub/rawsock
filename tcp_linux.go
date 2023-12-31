package raw

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type RawTCP struct {
	laddr, raddr *net.TCPAddr
	tcpFd        int

	raw *net.IPConn
}

func BindRawTCP(laddr, raddr *net.TCPAddr) (*RawTCP, error) {
	var l = &RawTCP{raddr: raddr}
	if laddr == nil {
		laddr = &net.TCPAddr{}
	}

	var err error
	if l.raddr == nil {
		l.raw, err = net.ListenIP("ip:tcp",
			&net.IPAddr{IP: laddr.IP, Zone: laddr.Zone},
		)
	} else {
		l.raw, err = net.DialIP("ip:tcp",
			&net.IPAddr{IP: laddr.IP, Zone: laddr.Zone},
			&net.IPAddr{IP: raddr.IP, Zone: raddr.Zone},
		)
	}
	if err != nil {
		return nil, err
	} else {
		loc := l.raw.LocalAddr().(*net.IPAddr)
		l.laddr = &net.TCPAddr{IP: loc.IP, Zone: loc.Zone}
	}

	if err = l.bindLocal(); err != nil {
		l.raw.Close()
		return nil, err
	}

	if err = l.setBpf(); err != nil {
		l.raw.Close()
		unix.Close(l.tcpFd)
		return nil, err
	}

	return nil, nil
}

// bindLocal for EADDRINUSE
func (l *RawTCP) bindLocal() error {
	nip, ok := netip.AddrFromSlice(l.laddr.IP)
	if !ok {
		return fmt.Errorf("invalid local ip address %s", l.laddr.IP)
	}

	var err error

	if nip.Is4() {
		l.tcpFd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}

		err = unix.Bind(l.tcpFd, &unix.SockaddrInet4{Addr: [4]byte(l.laddr.IP), Port: l.laddr.Port})
		if err != nil {
			return err
		} else if l.laddr.Port == 0 {
			sa, err := unix.Getsockname(l.tcpFd)
			if err != nil {
				unix.Close(l.tcpFd)
				return err
			}
			l.laddr.Port = sa.(*unix.SockaddrInet4).Port
		}
	} else {
		l.tcpFd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}

		zoneIdx := 0
		if l.laddr.Zone != "" {
			ifi, err := net.InterfaceByName(l.laddr.Zone)
			if err != nil {
				return err
			}
			zoneIdx = ifi.Index
		}
		laddr := &unix.SockaddrInet6{Addr: nip.As16(), Port: l.laddr.Port, ZoneId: uint32(zoneIdx)}
		if err = unix.Bind(l.tcpFd, laddr); err != nil {
			return err
		} else if l.laddr.Port == 0 {
			sa, err := unix.Getsockname(l.tcpFd)
			if err != nil {
				unix.Close(l.tcpFd)
				return err
			}
			l.laddr.Port = sa.(*unix.SockaddrInet6).Port
		}
	}

	return nil
}

func (l *RawTCP) setBpf() error {
	var ins = []bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtPayloadOffset},
	}
	if l.raddr != nil {
		ins = append(ins, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 0, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(l.raddr.Port), SkipTrue: 1},
			bpf.RetConstant{Val: 0},
		}...)
	}
	ins = append(ins, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(l.laddr.Port), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		bpf.RetConstant{Val: 0xffff},
	}...)

	var prog *unix.SockFprog
	if raw, err := bpf.Assemble(ins); err != nil {
		return err
	} else {
		prog = &unix.SockFprog{
			Len:    uint16(len(raw)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&raw[0])),
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

func (r *RawTCP) Read(b []byte) (n int, err error) {
	return r.raw.Read(b)
}
func (r *RawTCP) Write(b []byte) (n int, err error) {
	return r.raw.Write(b)
}
func (r *RawTCP) WriteTo(b []byte, ip *net.IPAddr) (n int, err error) {
	return r.raw.WriteToIP(b, ip)
}
func (r *RawTCP) Close() error {
	var err error
	if e := r.raw.Close(); err != nil {
		err = e
	}
	if e := unix.Close(r.tcpFd); err != nil {
		err = e
	}
	return err
}
func (r *RawTCP) LocalAddr() net.Addr  { return r.laddr }
func (r *RawTCP) RemoteAddr() net.Addr { return r.raddr }
func (r *RawTCP) SetDeadline(t time.Time) error {
	return r.raw.SetDeadline(t)
}
func (r *RawTCP) SetReadDeadline(t time.Time) error {
	return r.raw.SetReadDeadline(t)
}
func (r *RawTCP) SetWriteDeadline(t time.Time) error {
	return r.raw.SetWriteDeadline(t)
}
func (r *RawTCP) SyscallConn() (syscall.RawConn, error) {
	return r.raw.SyscallConn()
}
