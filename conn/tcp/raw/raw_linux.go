//go:build linux
// +build linux

package raw

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lysShub/sockit/conn"
	iconn "github.com/lysShub/sockit/conn/internal"
	itcp "github.com/lysShub/sockit/conn/tcp/internal"
	"github.com/lysShub/sockit/packet"
	"github.com/pkg/errors"

	"github.com/lysShub/sockit/helper/bpf"
	"github.com/lysShub/sockit/helper/ipstack"
	"github.com/lysShub/sockit/test"
	"github.com/lysShub/sockit/test/debug"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Listener struct {
	addr netip.AddrPort
	cfg  *conn.Config

	tcp *net.TCPListener

	raw *net.IPConn

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []itcp.ClosedTCPInfo
	closedConnsMu sync.RWMutex

	closeErr atomic.Pointer[error]
}

var _ conn.Listener = (*Listener)(nil)

func Listen(laddr netip.AddrPort, opts ...conn.Option) (*Listener, error) {
	var l = &Listener{
		cfg:   conn.Options(opts...),
		conns: make(map[netip.AddrPort]uint32, 16),
	}

	var err error
	l.tcp, l.addr, err = iconn.ListenLocal(laddr, l.cfg.UsedPort)
	if err != nil {
		return nil, l.close(err)
	}
	err = iconn.SetTSOByAddr(l.addr.Addr(), l.cfg.TSO)
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
	if l.closeErr.CompareAndSwap(nil, &os.ErrClosed) {
		if cause != nil {
			l.closeErr.Store(&cause)
		}
		if l.tcp != nil {
			if err := l.tcp.Close(); err != nil {
				l.closeErr.Store(&err)
			}
		}
		if l.raw != nil {
			if err := l.raw.Close(); err != nil {
				l.closeErr.Store(&err)
			}
		}
	}
	return *l.closeErr.Load()
}

func (l *Listener) Addr() netip.AddrPort {
	return l.addr
}

// todo: not support private proto that not start with tcp SYN flag
func (l *Listener) Accept() (conn.RawConn, error) {
	var min, max = itcp.TcpSynSizeRange(l.addr.Addr().Is4())

	var ip = make([]byte, max)
	for {
		n, err := l.raw.Read(ip[:max])
		if err != nil {
			return nil, err
		} else if n < min {
			return nil, fmt.Errorf("recved invalid ip packet, bytes %d", n)
		}
		l.purgeDeleted()

		var raddr netip.AddrPort
		var isn uint32
		switch header.IPVersion(ip) {
		case 4:
			iphdr := header.IPv4(ip[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			isn = tcphdr.SequenceNumber()
		case 6:
			iphdr := header.IPv6(ip[:n])
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
			if err := c.init(l.cfg); err != nil {
				return nil, c.close(err)
			}
			return c, nil
		}
	}
}

func (l *Listener) purgeDeleted() {
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

func (l *Listener) deleteConn(raddr netip.AddrPort, isn uint32) error {
	if l == nil {
		return nil
	}
	l.closedConnsMu.Lock()
	defer l.closedConnsMu.Unlock()

	l.closedConns = append(
		l.closedConns,
		itcp.ClosedTCPInfo{
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

func (l *Listener) Close() error {
	return l.close(nil)
}

// NOTICE: probably recv reassembled tcp segment, that greater than MTU
type Conn struct {
	laddr, raddr netip.AddrPort
	isn          uint32
	tcp          *net.TCPListener
	complete     bool

	raw *net.IPConn

	ipstack *ipstack.IPStack

	ctxPeriod time.Duration

	closeFn  itcp.CloseCallback
	closeErr atomic.Pointer[error]
}

var _ conn.RawConn = (*Conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...conn.Option) (*Conn, error) {
	cfg := conn.Options(opts...)
	var c = newConnect(
		laddr, raddr, 0,
		nil, cfg.CtxPeriod,
	)

	var err error
	c.tcp, c.laddr, err = iconn.ListenLocal(laddr, cfg.UsedPort)
	if err != nil {
		return nil, c.close(err)
	}
	if err = iconn.SetTSOByAddr(c.laddr.Addr(), cfg.TSO); err != nil {
		return nil, c.close(err)
	}

	return c, c.init(cfg)
}

func newConnect(laddr, raddr netip.AddrPort, isn uint32, closeCall itcp.CloseCallback, ctxPeriod time.Duration) *Conn {
	return &Conn{
		laddr:     laddr,
		raddr:     raddr,
		isn:       isn,
		closeFn:   closeCall,
		ctxPeriod: ctxPeriod,
	}
}

func (c *Conn) init(cfg *conn.Config) (err error) {
	c.raw, err = net.DialIP(
		"ip:tcp",
		&net.IPAddr{IP: c.laddr.Addr().AsSlice(), Zone: c.laddr.Addr().Zone()},
		&net.IPAddr{IP: c.raddr.Addr().AsSlice(), Zone: c.raddr.Addr().Zone()},
	)
	if err != nil {
		return err
	}

	raw, err := c.raw.SyscallConn()
	if err != nil {
		return err
	}

	// filter src/dst ports
	if err = bpf.SetRawBPF(
		raw,
		bpf.FilterPorts(c.raddr.Port(), c.laddr.Port()),
	); err != nil {
		return err
	}

	if c.ipstack, err = ipstack.New(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber,
		cfg.IPStack.Unmarshal(),
	); err != nil {
		return err
	}

	c.complete = cfg.NotTrunc
	return nil
}

func (c *Conn) close(cause error) error {
	if c.closeErr.CompareAndSwap(nil, &os.ErrClosed) {
		if cause != nil {
			c.closeErr.Store(&cause)
		}
		if c.closeFn != nil {
			if err := c.closeFn(c.raddr, c.isn); err != nil {
				c.closeErr.Store(&err)
			}
		}
		if c.tcp != nil {
			if err := c.tcp.Close(); err != nil {
				c.closeErr.Store(&err)
			}
		}
		if c.raw != nil {
			if err := c.raw.Close(); err != nil {
				c.closeErr.Store(&err)
			}
		}
	}
	return *c.closeErr.Load()
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
	if debug.Debug() {
		test.ValidIP(test.T(), pkt.Bytes())
	}
	switch header.IPVersion(b) {
	case 4:
		if c.complete && !iconn.CompleteCheck(true, pkt.Bytes()) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		pkt.SetHead(pkt.Head() + int(header.IPv4(b).HeaderLength()))
	case 6:
		if c.complete && !iconn.CompleteCheck(false, pkt.Bytes()) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		pkt.SetHead(pkt.Head() + header.IPv6MinimumSize)
	}
	return nil
}

func (c *Conn) Write(ctx context.Context, pkt *packet.Packet) (err error) {
	_, err = c.raw.Write(pkt.Bytes())
	return err
}

func (c *Conn) Inject(ctx context.Context, pkt *packet.Packet) (err error) {
	c.ipstack.AttachInbound(pkt)
	if debug.Debug() {
		test.ValidIP(test.T(), pkt.Bytes())
	}
	_, err = c.raw.Write(pkt.Bytes())
	return err
}

func (c *Conn) Close() error {
	return c.close(nil)
}

func (c *Conn) LocalAddr() netip.AddrPort  { return c.laddr }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.raddr }
