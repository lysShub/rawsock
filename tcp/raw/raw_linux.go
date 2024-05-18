//go:build linux
// +build linux

package raw

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/helper"
	"github.com/lysShub/rawsock/helper/bind"
	itcp "github.com/lysShub/rawsock/tcp/internal"
	"github.com/pkg/errors"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/helper/bpf"
	"github.com/lysShub/rawsock/helper/ipstack"
	"github.com/lysShub/rawsock/test"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Listener struct {
	addr netip.AddrPort
	cfg  *rawsock.Config

	tcp *net.TCPListener

	raw *net.IPConn

	// AddrPort:ISN
	conns   map[itcp.ID]struct{}
	connsMu sync.RWMutex

	closeErr errorx.CloseErr
}

var _ rawsock.Listener = (*Listener)(nil)

func Listen(laddr netip.AddrPort, opts ...rawsock.Option) (*Listener, error) {
	var l = &Listener{
		cfg:   rawsock.Options(opts...),
		conns: make(map[itcp.ID]struct{}, 16),
	}
	var err error

	// usaully should listen on all nic, but we juse listen on default nic
	if laddr.Addr().IsUnspecified() {
		laddr = netip.AddrPortFrom(rawsock.LocalAddr(), laddr.Port())
	}

	l.tcp, l.addr, err = bind.ListenLocal(laddr, l.cfg.UsedPort)
	if err != nil {
		return nil, l.close(err)
	}

	l.raw, err = net.ListenIP(
		"ip:tcp",
		&net.IPAddr{IP: l.addr.Addr().AsSlice(), Zone: laddr.Addr().Zone()},
	)
	if err != nil {
		return nil, l.close(err)
	}

	raw, err := l.raw.SyscallConn()
	if err != nil {
		return nil, l.close(err)
	}

	if err = bpf.SetRawBPF(
		raw,
		bpf.FilterDstPortAndSynFlag(l.addr.Port()),
	); err != nil {
		return nil, l.close(err)
	}

	return l, nil
}

func (l *Listener) close(cause error) error {
	return l.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if l.raw != nil {
			errs = append(errs, l.raw.Close())
		}
		if l.tcp != nil {
			errs = append(errs, errors.WithStack(l.tcp.Close()))
		}
		return
	})
}

// todo: not support private proto that not start with tcp SYN flag
func (l *Listener) Accept() (rawsock.RawConn, error) {
	var min, max = itcp.SizeRange(l.addr.Addr().Is4())

	var ip = make([]byte, max)
	for {
		n, err := l.raw.Read(ip[:max])
		if err != nil {
			return nil, l.close(err)
		} else if n < min {
			return nil, fmt.Errorf("recved invalid ip packet, bytes %d", n)
		}

		var id = itcp.ID{Local: l.addr}
		switch header.IPVersion(ip) {
		case 4:
			iphdr := header.IPv4(ip[:n])
			tcphdr := header.TCP(iphdr.Payload())
			id.Remote = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			id.ISN = tcphdr.SequenceNumber()
		case 6:
			iphdr := header.IPv6(ip[:n])
			tcphdr := header.TCP(iphdr.Payload())
			id.Remote = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			id.ISN = tcphdr.SequenceNumber()
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

			c := newConnect(
				id, l.deleteConn, l.cfg.CtxPeriod,
			)

			if err := c.init(l.cfg); err != nil {
				return nil, errorx.WrapTemp(c.close(err))
			}
			return c, nil
		}
	}
}

func (l *Listener) deleteConn(id itcp.ID) error {
	if l == nil {
		return nil
	}
	time.AfterFunc(time.Minute, func() {
		l.connsMu.Lock()
		defer l.connsMu.Unlock()

		delete(l.conns, id)
	})
	return nil
}

func (l *Listener) Addr() netip.AddrPort { return l.addr }
func (l *Listener) Close() error         { return l.close(nil) }

type Conn struct {
	itcp.ID
	tcp *net.TCPListener

	raw *net.IPConn

	ipstack *ipstack.IPStack

	ctxPeriod time.Duration

	closeFn  itcp.CloseCallback
	closeErr errorx.CloseErr
}

var _ rawsock.RawConn = (*Conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (*Conn, error) {
	cfg := rawsock.Options(opts...)

	if l, err := helper.DefaultLocal(laddr.Addr(), raddr.Addr()); err != nil {
		return nil, errors.WithStack(err)
	} else {
		laddr = netip.AddrPortFrom(l, laddr.Port())
	}

	tcp, laddr, err := bind.ListenLocal(laddr, cfg.UsedPort)
	if err != nil {
		return nil, err
	}

	var c = newConnect(
		itcp.ID{Local: laddr, Remote: raddr, ISN: 0},
		nil, cfg.CtxPeriod,
	)
	c.tcp = tcp

	if err = c.init(cfg); err != nil {
		return nil, c.close(err)
	}
	return c, nil
}

func newConnect(id itcp.ID, closeCall itcp.CloseCallback, ctxPeriod time.Duration) *Conn {
	return &Conn{
		ID:        id,
		closeFn:   closeCall,
		ctxPeriod: ctxPeriod,
	}
}

func (c *Conn) init(cfg *rawsock.Config) (err error) {
	if c.raw, err = net.DialIP(
		"ip:tcp",
		&net.IPAddr{IP: c.Local.Addr().AsSlice(), Zone: c.Local.Addr().Zone()},
		&net.IPAddr{IP: c.ID.Remote.Addr().AsSlice(), Zone: c.ID.Remote.Addr().Zone()},
	); err != nil {
		return err
	}

	// todo: set nic offload should be options, some option can't be update: rx-gro-hw: on [fixed]
	// todo: if loopback, should set tso/gso:
	//   ethtool -K lo tcp-segmentation-offload off
	//   ethtool -K lo generic-segmentation-offload off
	if err = bind.SetGRO(
		c.Local.Addr(), c.Remote.Addr(), cfg.GRO,
	); err != nil {
		return err
	}

	// filter src/dst ports
	if raw, err := c.raw.SyscallConn(); err != nil {
		return err
	} else {
		if err = bpf.SetRawBPF(
			raw,
			bpf.FilterPorts(c.ID.Remote.Port(), c.Local.Port()),
		); err != nil {
			return err
		}
	}

	if c.ipstack, err = ipstack.New(
		c.Local.Addr(), c.ID.Remote.Addr(),
		header.TCPProtocolNumber,
		cfg.IPStack.Unmarshal(),
	); err != nil {
		return err
	}
	return nil
}

func (c *Conn) close(cause error) error {
	return c.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		if c.tcp != nil {
			errs = append(errs, errors.WithStack(c.tcp.Close()))
		}
		if c.closeFn != nil {
			errs = append(errs, c.closeFn(c.ID))
		}
		return
	})
}

func (c *Conn) Read(ctx context.Context, pkt *packet.Packet) (err error) {
	b := pkt.Bytes()

	var n int
	for {
		err = c.raw.SetReadDeadline(time.Now().Add(c.ctxPeriod))
		if err != nil {
			return err
		}

		n, err = c.raw.Read(b[:cap(b)])
		if err == nil {
			break
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		} else {
			return err
		}
	}
	pkt.SetData(n)

	hdrLen, err := helper.IntegrityCheck(pkt.Bytes())
	if err != nil {
		return err
	}
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	pkt.SetHead(pkt.Head() + int(hdrLen))
	return nil
}

func (c *Conn) Write(_ context.Context, pkt *packet.Packet) (err error) {
	_, err = c.raw.Write(pkt.Bytes())
	return err
}

func (c *Conn) Inject(_ context.Context, pkt *packet.Packet) (err error) {
	defer pkt.DetachN(c.ipstack.Size())
	c.ipstack.AttachInbound(pkt)
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	_, err = c.raw.Write(pkt.Bytes())
	return err
}

func (c *Conn) Close() error {
	return c.close(nil)
}

func (c *Conn) LocalAddr() netip.AddrPort  { return c.Local }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.ID.Remote }
