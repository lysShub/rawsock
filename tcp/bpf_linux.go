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

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
	"github.com/lysShub/relraw/internal/bpf"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/config/ipstack"
	"github.com/lysShub/relraw/test"
	"github.com/lysShub/relraw/test/debug"
	"golang.org/x/sys/unix"
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

var _ relraw.Listener = (*listener)(nil)

func Listen(laddr netip.AddrPort, opts ...relraw.Option) (*listener, error) {
	var l = &listener{
		cfg:   relraw.Options(opts...),
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
func (l *listener) Accept() (relraw.RawConn, error) {
	var min, max int = header.TCPMinimumSize, header.TCPHeaderMaximumSize
	if l.addr.Addr().Is4() {
		min += header.IPv4MinimumSize
		max += header.IPv4MaximumHeaderSize
	} else {
		min += header.IPv6MinimumSize
		max += header.IPv6MinimumSize
	}

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
				l.deleteConn, l.cfg.CtxCancelDelay,
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

	ipstack *relraw.IPStack

	ctxCancelDelay time.Duration

	closeFn closeCallback
}

var _ relraw.RawConn = (*conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...relraw.Option) (*conn, error) {
	cfg := relraw.Options(opts...)

	var c = newConnect(
		laddr, raddr, 0,
		nil, cfg.CtxCancelDelay,
	)
	var err error

	c.tcp, c.laddr, err = internal.ListenLocal(laddr, cfg.UsedPort)
	if err != nil {
		c.Close()
		return nil, err
	}

	return c, c.init(cfg.CompleteCheck, cfg.IPStackCfg)
}

func newConnect(laddr, raddr netip.AddrPort, isn uint32, closeCall closeCallback, ctxDelay time.Duration) *conn {
	return &conn{
		laddr:          laddr,
		raddr:          raddr,
		isn:            isn,
		closeFn:        closeCall,
		ctxCancelDelay: ctxDelay,
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

	// read ip header
	e := raw.Control(func(fd uintptr) {
		err = unix.SetsockoptByte(int(fd), unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		if err != nil {
			return
		}
	})
	if e != nil {
		c.Close()
		return e
	} else if err != nil {
		c.Close()
		return err
	}

	if c.ipstack, err = relraw.NewIPStack(
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

func (c *conn) Read(ip []byte) (n int, err error) {
	n, err = c.raw.Read(ip)
	if err == nil {
		c.ipstack.UpdateInbound(ip[:n])
		if debug.Debug() {
			test.ValidIP(test.T(), ip[:n])
		}
	}

	if c.complete && !internal.CompleteCheck(c.ipstack.IPv4(), ip[:n]) {
		return 0, errors.WithStack(io.ErrShortBuffer)
	}
	return n, err
}

func (c *conn) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	b := p.Data()
	b = b[:cap(b)]

	var n int
	for {
		err = c.raw.SetReadDeadline(time.Now().Add(c.ctxCancelDelay))
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

func (c *conn) Write(ip []byte) (n int, err error) {
	c.ipstack.UpdateOutbound(ip)
	if debug.Debug() {
		test.ValidIP(test.T(), ip)
	}
	return c.raw.Write(ip)
}

func (c *conn) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	c.ipstack.AttachOutbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}
	_, err = c.raw.Write(p.Data())
	return err
}

func (c *conn) Inject(ip []byte) (err error) {
	c.ipstack.UpdateInbound(ip)
	if debug.Debug() {
		test.ValidIP(test.T(), ip)
	}
	_, err = c.raw.Write(ip)
	return err
}

func (c *conn) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
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
		if e := c.Close(); e != nil {
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
