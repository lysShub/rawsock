//go:build linux
// +build linux

package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/rsocket"
	"github.com/lysShub/rsocket/internal"
	"github.com/lysShub/rsocket/internal/bpf"
	"github.com/lysShub/rsocket/internal/config"
	"github.com/lysShub/rsocket/internal/config/ipstack"
	"github.com/lysShub/rsocket/test"
	"github.com/lysShub/rsocket/test/debug"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listener struct {
	addr netip.AddrPort
	cfg  *config.Config

	tcp *net.TCPListener

	raw *net.IPConn

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []closedTCPInfo
	closedConnsMu sync.RWMutex
}

var _ rsocket.Listener = (*listener)(nil)

func Listen(laddr netip.AddrPort, opts ...rsocket.Option) (*listener, error) {
	var l = &listener{
		cfg:   rsocket.Options(opts...),
		conns: make(map[netip.AddrPort]uint32, 16),
	}

	var err error
	l.tcp, l.addr, err = internal.ListenLocal(laddr, l.cfg.UsedPort)
	if err != nil {
		l.Close()
		return nil, err
	}

	l.raw, err = net.ListenIP(
		"ip:tcp",
		&net.IPAddr{IP: l.addr.Addr().AsSlice(), Zone: laddr.Addr().Zone()},
	)
	if err != nil {
		l.Close()
		return nil, err
	}

	raw, err := l.raw.SyscallConn()
	if err != nil {
		l.Close()
		return nil, err
	}

	if err = bpf.SetBPF(
		raw,
		bpf.FilterDstPortAndSynFlag(l.addr.Port()),
	); err != nil {
		l.Close()
		return nil, err
	}

	return l, nil
}

func (l *listener) Close() error {
	var err error
	if l.tcp != nil {
		if e := l.Close(); e != nil {
			err = e
		}
	}
	if l.raw != nil {
		if e := l.raw.Close(); e != nil {
			err = e
		}
	}
	return err
}

func (l *listener) Addr() netip.AddrPort {
	return l.addr
}

// todo: not support private proto that not start with tcp SYN flag
func (l *listener) Accept() (rsocket.RawConn, error) {
	var min, max = tcpSynSizeRange(l.addr.Addr().Is4())

	var b = make([]byte, max)
	for {
		n, err := l.raw.Read(b[:max])
		if err != nil {
			return nil, err
		} else if n < min {
			return nil, fmt.Errorf("recved invalid ip packet, bytes %d", n)
		}
		l.purgeDeleted()

		var raddr netip.AddrPort
		var isn uint32
		switch header.IPVersion(b) {
		case 4:
			iphdr := header.IPv4(b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			isn = tcphdr.SequenceNumber()
		case 6:
			iphdr := header.IPv6(b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			isn = tcphdr.SequenceNumber()
		default:
			continue
		}

		newConn := false
		old, ok := l.conns[raddr]
		if !ok || (ok && old != isn) {
			l.conns[raddr] = isn
			newConn = true
		}

		if newConn {
			c := newConnect(
				l.addr, raddr, isn,
				l.deleteConn, l.cfg.CtxPeriod,
			)
			return c, c.init(l.cfg.CompleteCheck, l.cfg.IPStackCfg)
		}
	}
}

func (l *listener) purgeDeleted() {
	l.closedConnsMu.Lock()
	defer l.closedConnsMu.Unlock()

	for i := len(l.closedConns) - 1; i >= 0; i-- {
		c := l.closedConns[i]

		if time.Since(c.DeleteAt) > time.Minute {
			isn, ok := l.conns[c.Raddr]
			if ok && isn == c.ISN {
				delete(l.conns, c.Raddr)
			}

			l.closedConns = l.closedConns[:i-1]
		} else {
			break
		}
	}
}

func (l *listener) deleteConn(raddr netip.AddrPort, isn uint32) error {
	if l == nil {
		return nil
	}
	l.closedConnsMu.Lock()
	defer l.closedConnsMu.Unlock()

	l.closedConns = append(
		l.closedConns,
		closedTCPInfo{
			DeleteAt: time.Now(),
			Raddr:    raddr,
			ISN:      isn,
		},
	)

	// desc
	sort.Slice(l.closedConns, func(i, j int) bool {
		it := l.closedConns[i].DeleteAt
		jt := l.closedConns[i].DeleteAt
		return it.After(jt)
	})
	return nil
}

type conn struct {
	laddr, raddr netip.AddrPort
	isn          uint32
	tcp          *net.TCPListener
	complete     bool

	raw *net.IPConn

	ipstack *rsocket.IPStack

	ctxPeriod time.Duration

	closeFn closeCallback
}

var _ rsocket.RawConn = (*conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...rsocket.Option) (*conn, error) {
	cfg := rsocket.Options(opts...)

	var c = newConnect(
		laddr, raddr, 0,
		nil, cfg.CtxPeriod,
	)
	var err error

	c.tcp, c.laddr, err = internal.ListenLocal(laddr, cfg.UsedPort)
	if err != nil {
		c.Close()
		return nil, err
	}

	return c, c.init(cfg.CompleteCheck, cfg.IPStackCfg)
}

func newConnect(laddr, raddr netip.AddrPort, isn uint32, closeCall closeCallback, ctxPeriod time.Duration) *conn {
	return &conn{
		laddr:     laddr,
		raddr:     raddr,
		isn:       isn,
		closeFn:   closeCall,
		ctxPeriod: ctxPeriod,
	}
}

func (c *conn) init(complete bool, ipCfg *ipstack.Options) (err error) {
	c.raw, err = net.DialIP(
		"ip:tcp",
		&net.IPAddr{IP: c.laddr.Addr().AsSlice(), Zone: c.laddr.Addr().Zone()},
		&net.IPAddr{IP: c.raddr.Addr().AsSlice(), Zone: c.raddr.Addr().Zone()},
	)
	if err != nil {
		c.Close()
		return err
	}

	raw, err := c.raw.SyscallConn()
	if err != nil {
		c.Close()
		return err
	}

	// filter src/dst ports
	if err = bpf.SetBPF(
		raw,
		bpf.FilterSrcPortAndDstPort(c.raddr.Port(), c.laddr.Port()),
	); err != nil {
		c.Close()
		return err
	}

	if c.ipstack, err = rsocket.NewIPStack(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber,
		ipCfg.Unmarshal(),
	); err != nil {
		c.Close()
		return err
	}

	c.complete = complete
	return nil
}

func (c *conn) Read(ctx context.Context, p *rsocket.Packet) (err error) {
	b := p.Data()
	b = b[:cap(b)]

	var n int
	for {
		err = c.raw.SetReadDeadline(time.Now().Add(c.ctxPeriod))
		if err != nil {
			return err
		}

		n, err = c.raw.Read(b)
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
	p.SetLen(n)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}
	switch header.IPVersion(b) {
	case 4:
		if c.complete && !internal.CompleteCheck(true, p.Data()) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		p.SetHead(p.Head() + int(header.IPv4(b).HeaderLength()))
	case 6:
		if c.complete && !internal.CompleteCheck(false, p.Data()) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		p.SetHead(p.Head() + header.IPv6MinimumSize)
	}
	return nil
}

func (c *conn) Write(ctx context.Context, p *rsocket.Packet) (err error) {
	_, err = c.raw.Write(p.Data())
	return err
}

func (c *conn) Inject(ctx context.Context, p *rsocket.Packet) (err error) {
	c.ipstack.AttachInbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}
	_, err = c.raw.Write(p.Data())
	return err
}

func (c *conn) Close() error {
	var err error
	if c.closeFn != nil {
		if e := c.closeFn(c.raddr, c.isn); e != nil {
			err = e
		}
	}
	if c.tcp != nil {
		if e := c.tcp.Close(); e != nil {
			err = e
		}
	}
	if c.raw != nil {
		if e := c.raw.Close(); e != nil {
			err = e
		}
	}
	return err
}

func (c *conn) LocalAddr() netip.AddrPort {
	return c.laddr
}
func (c *conn) RemoteAddr() netip.AddrPort {
	return c.raddr
}
