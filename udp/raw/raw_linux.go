//go:build linux
// +build linux

package raw

import (
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/helper"
	"github.com/lysShub/rawsock/helper/bind"
	"github.com/lysShub/rawsock/helper/bpf"
	"github.com/lysShub/rawsock/helper/ipstack"
	"github.com/lysShub/rawsock/test"
	iudp "github.com/lysShub/rawsock/udp/internal"
	"github.com/pkg/errors"
)

type Listener struct {
	addr netip.AddrPort
	cfg  *rawsock.Config

	udp int // unix fd

	raw *net.IPConn

	conns   map[netip.AddrPort]struct{}
	connsMu sync.RWMutex

	closeErr errorx.CloseErr
}

var _ rawsock.Listener = (*Listener)(nil)

func Listen(laddr netip.AddrPort, opts ...rawsock.Option) (*Listener, error) {
	var l = &Listener{
		cfg:   rawsock.Options(opts...),
		conns: make(map[netip.AddrPort]struct{}, 16),
	}
	var err error

	// usaully should listen on all nic, but we juse listen on default nic
	if laddr.Addr().IsUnspecified() {
		laddr = netip.AddrPortFrom(rawsock.LocalAddr(), laddr.Port())
	}

	l.udp, l.addr, err = bind.BindLocal(header.UDPProtocolNumber, laddr, l.cfg.UsedPort)
	if err != nil {
		return nil, l.close(err)
	}

	l.raw, err = net.ListenIP(
		"ip:udp",
		&net.IPAddr{IP: l.addr.Addr().AsSlice(), Zone: laddr.Addr().Zone()},
	)
	if err != nil {
		return nil, l.close(err)
	}

	// todo: bpf can return IPv4HeaderSize+8
	if raw, err := l.raw.SyscallConn(); err != nil {
		return nil, l.close(err)
	} else {
		if err = bpf.SetRawBPF(
			raw,
			bpf.FilterDstPort(l.addr.Port()),
		); err != nil {
			return nil, l.close(err)
		}
	}

	return l, nil
}

func (l *Listener) close(cause error) error {
	return l.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if l.udp != 0 {
			errs = append(errs, errors.WithStack(unix.Close(l.udp)))
		}
		if l.raw != nil {
			errs = append(errs, errors.WithStack(l.raw.Close()))
		}
		return errs
	})
}

func (l *Listener) Accept() (rawsock.RawConn, error) {
	min, max := iudp.SizeRange(l.addr.Addr().Is4())

	var ip = make([]byte, max)
	for {
		n, err := l.raw.Read(ip[:max])
		if err != nil {
			return nil, errors.WithStack(err)
		} else if n < min {
			return nil, errors.Errorf("recved invalid ip packet, bytes %d", n)
		}

		var id netip.AddrPort
		switch header.IPVersion(ip) {
		case 4:
			iphdr := header.IPv4(ip[:n])
			id = netip.AddrPortFrom(
				netip.AddrFrom4(iphdr.SourceAddress().As4()),
				header.UDP(iphdr[iphdr.HeaderLength():]).SourcePort(),
			)
		case 6:
			iphdr := header.IPv6(ip[:n])
			id = netip.AddrPortFrom(
				netip.AddrFrom16(iphdr.SourceAddress().As16()),
				header.UDP(iphdr[header.IPv6FixedHeaderSize:]).SourcePort(),
			)
		default:
			continue
		}

		l.connsMu.RLock()
		_, has := l.conns[id]
		l.connsMu.RUnlock()
		if !has {
			l.connsMu.Lock()
			l.conns[id] = struct{}{}
			l.connsMu.Unlock()

			c := newConnect(l.addr, id, l.deleteConn)
			if err := c.init(l.cfg); err != nil {
				return nil, errorx.WrapTemp(c.close(err))
			}
			return c, nil
		}
	}
}

func (l *Listener) deleteConn(raddr netip.AddrPort) error {
	if l == nil {
		return nil
	}
	l.connsMu.Lock()
	delete(l.conns, raddr)
	l.connsMu.Unlock()
	return nil
}
func (l *Listener) Addr() netip.AddrPort { return l.addr }
func (l *Listener) Close() error         { return l.close(nil) }

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (*Conn, error) {
	cfg := rawsock.Options(opts...)

	if l, err := helper.DefaultLocal(laddr.Addr(), raddr.Addr()); err != nil {
		return nil, errors.WithStack(err)
	} else {
		laddr = netip.AddrPortFrom(l, laddr.Port())
	}

	fd, laddr, err := bind.BindLocal(header.UDPProtocolNumber, laddr, cfg.UsedPort)
	if err != nil {
		return nil, err
	}

	var c = newConnect(laddr, raddr, nil)
	c.udp = fd

	if err := c.init(cfg); err != nil {
		return nil, c.close(err)
	}
	return c, nil
}

type Conn struct {
	laddr, raddr  netip.AddrPort
	closeCallback iudp.CloseCallback

	udp int

	// todo: UDPConn set
	raw     *net.IPConn
	ipstack *ipstack.IPStack

	closeErr errorx.CloseErr
}

var _ rawsock.RawConn = (*Conn)(nil)

func (c *Conn) close(cause error) error {
	return c.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if c.closeCallback != nil {
			errs = append(errs, c.closeCallback(c.RemoteAddr()))
		}
		if c.udp != 0 {
			errs = append(errs, errors.WithStack(syscall.Close(c.udp)))
		}
		if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		return
	})
}
func newConnect(laddr, raddr netip.AddrPort, close iudp.CloseCallback) *Conn {
	return &Conn{laddr: laddr, raddr: raddr, closeCallback: close}
}

func (c *Conn) init(cfg *rawsock.Config) (err error) {
	if c.raw, err = net.DialIP(
		"ip:udp",
		&net.IPAddr{IP: c.laddr.Addr().AsSlice()},
		&net.IPAddr{IP: c.raddr.Addr().AsSlice()},
	); err != nil {
		return errors.WithStack(err)
	}

	if cfg.SetGRO {
		if err = bind.SetGRO(c.laddr.Addr(), c.raddr.Addr(), false); err != nil {
			return err
		}
	}

	if raw, err := c.raw.SyscallConn(); err != nil {
		return errors.WithStack(err)
	} else {
		err := bpf.SetRawBPF(raw,
			bpf.FilterPorts(c.raddr.Port(), c.laddr.Port()),
		)
		if err != nil {
			return err
		}
	}

	if c.ipstack, err = ipstack.New(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber,
		cfg.IPStack.Unmarshal(),
	); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Read(pkt *packet.Packet) (err error) {
	n, err := c.raw.Read(pkt.Bytes())
	if err != nil {
		return err
	}
	pkt.SetData(n)

	hdrLen, err := helper.IPCheck(pkt.Bytes())
	if err != nil {
		return err
	}
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	pkt.SetHead(pkt.Head() + int(hdrLen))
	return nil
}
func (c *Conn) Write(pkt *packet.Packet) (err error) {
	_, err = c.raw.Write(pkt.Bytes())
	return err
}
func (c *Conn) Inject(pkt *packet.Packet) (err error) {
	defer pkt.DetachN(c.ipstack.Size())
	c.ipstack.AttachInbound(pkt)
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	_, err = c.raw.Write(pkt.Bytes())
	return err
}

func (c *Conn) LocalAddr() netip.AddrPort  { return c.laddr }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.raddr }
func (c *Conn) Close() error               { return c.close(nil) }
