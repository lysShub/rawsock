package divert

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/sockit/conn"
	iconn "github.com/lysShub/sockit/conn/internal"
	itcp "github.com/lysShub/sockit/conn/tcp/internal"
	"github.com/lysShub/sockit/errorx"
	"github.com/lysShub/sockit/helper/ipstack"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/route"
	"github.com/lysShub/sockit/test"
	"github.com/lysShub/sockit/test/debug"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Listener struct {

	/*
		Structure

			handle priority      	describe

			a          			  listener read new conn's first packet P1

			a+1        			  connection from Accept, read corresponding packet（not sniff）

			a+2 or MAX_PRIORITY   after a+1 open, inject P1 use this handle（ignore current, tcp will send muti SYN packet）
	*/
	// todo: inject P1

	addr netip.AddrPort
	cfg  *conn.Config

	tcp windows.Handle

	raw *divert.Handle

	// priority int16

	conns   map[itcp.ID]struct{}
	connsMu sync.RWMutex

	closeErr atomic.Pointer[error]
}

var _ conn.Listener = (*Listener)(nil)

func Listen(locAddr netip.AddrPort, opts ...conn.Option) (*Listener, error) {
	var l = &Listener{
		cfg:   conn.Options(opts...),
		conns: make(map[itcp.ID]struct{}, 16),
	}

	var err error
	l.tcp, l.addr, err = iconn.BindLocal(locAddr, l.cfg.UsedPort)
	if err != nil {
		l.Close()
		return nil, err
	}

	var filter string
	if l.addr.Addr().IsLoopback() {
		filter = fmt.Sprintf(
			"tcp and remotePort=%d and remoteAddr=%s",
			l.addr.Port(), l.addr.Addr().String(),
		)
	} else {
		filter = fmt.Sprintf(
			"(loopback and tcp and remotePort=%d and remoteAddr=%s) or (!loopback and tcp and localPort=%d and localAddr=%s)",
			l.addr.Port(), l.addr.Addr().String(),
			l.addr.Port(), l.addr.Addr().String(),
		)
	}

	if l.raw, err = divert.Open(filter, divert.Network, l.cfg.DivertPriorty, divert.ReadOnly); err != nil {
		l.Close()
		return nil, err
	}
	return l, err
}

// set divert priority, for Listen will use p and p+1
func Priority(p int16) conn.Option {
	return func(c *conn.Config) {
		c.DivertPriorty = p
	}
}

func (l *Listener) close(cause error) error {
	if l.closeErr.CompareAndSwap(nil, &net.ErrClosed) {
		if l.tcp != 0 {
			if err := windows.Close(l.tcp); err != nil {
				cause = err
			}
		}
		if l.raw != nil {
			if err := l.raw.Close(); err != nil {
				cause = err
			}
		}

		if cause != nil {
			l.closeErr.Store(&cause)
		}
		return cause
	}
	return *l.closeErr.Load()
}

func (l *Listener) Addr() netip.AddrPort { return l.addr }

func (l *Listener) Accept() (conn.RawConn, error) {
	var min, max = itcp.SizeRange(l.addr.Addr().Is4())
	var addr divert.Address

	var b = make([]byte, max)
	for {
		n, err := l.raw.Recv(b[:max], &addr)
		if err != nil {
			return nil, l.close(err)
		} else if n < min {
			return nil, errors.Errorf("recved invalid ip packet, bytes %d", n)
		}

		var id = itcp.ID{Local: l.addr}
		switch header.IPVersion(b) {
		case 4:
			iphdr := header.IPv4(b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			id.Remote = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			id.ISN = tcphdr.SequenceNumber()
		case 6:
			iphdr := header.IPv6(b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			id.Remote = netip.AddrPortFrom(netip.AddrFrom16(iphdr.SourceAddress().As16()), tcphdr.SourcePort())
			id.ISN = tcphdr.SequenceNumber()
		default:
			return nil, fmt.Errorf("recv invalid ip packet: %s", hex.Dump(b[:n]))
		}

		l.connsMu.RLock()
		_, has := l.conns[id]
		l.connsMu.RUnlock()
		if !has {
			l.connsMu.Lock()
			l.conns[id] = struct{}{}
			l.connsMu.RLock()

			conn := newConnect(
				id,
				addr.Loopback(), int(addr.Network().IfIdx),
				l.deleteConn,
			)

			return conn, conn.init(l.cfg)
			// todo: inject P1
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

func (l *Listener) Close() error { return l.close(nil) }

type Conn struct {
	itcp.ID
	loopback bool

	tcp windows.Handle

	raw *divert.Handle

	injectAddr *divert.Address

	ipstack *ipstack.IPStack

	closeFn itcp.CloseCallback
}

var outboundAddr = func() *divert.Address {
	addr := &divert.Address{}
	addr.SetOutbound(true)
	// addr.Flags.IPChecksum() // todo: set false
	return addr
}()

var _ conn.RawConn = (*Conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...conn.Option) (*Conn, error) {
	cfg := conn.Options(opts...)

	tcp, laddr, err := iconn.BindLocal(laddr, cfg.UsedPort)
	if err != nil {
		return nil, err
	}

	var entry route.Entry
	if rows, err := route.GetTable(); err != nil {
		return nil, err
	} else {
		entry, err = rows.MatchRoot(raddr.Addr())
		if err != nil {
			return nil, err
		}
	}
	if laddr.Addr().IsUnspecified() {
		laddr = netip.AddrPortFrom(entry.Addr, laddr.Port())
	} else {
		if laddr.Addr() != entry.Addr {
			err = errors.WithMessagef(
				windows.ERROR_NETWORK_UNREACHABLE,
				"%s -> %s", laddr.Addr().String(), raddr.Addr().String(),
			)
			return nil, err
		}
	}

	loopback := divert.Loopback(laddr.Addr(), raddr.Addr())
	c := newConnect(
		itcp.ID{Local: laddr, Remote: raddr, ISN: 0},
		loopback, int(entry.Interface), nil,
	)
	c.tcp = tcp

	return c, c.init(cfg)
}

func newConnect(id itcp.ID, loopback bool, ifIdx int, closeCall itcp.CloseCallback) *Conn {
	var conn = &Conn{
		ID:         id,
		loopback:   loopback,
		injectAddr: &divert.Address{},
		closeFn:    closeCall,
	}
	conn.injectAddr.SetOutbound(false)
	conn.injectAddr.Network().IfIdx = uint32(ifIdx)

	return conn
}

func (c *Conn) init(cfg *conn.Config) (err error) {
	var filter string
	if c.loopback {
		// loopback recv as outbound packet, so raddr is localAddr laddr is remoteAddr
		filter = fmt.Sprintf(
			// outbound and
			"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			c.Remote.Port(), c.Remote.Addr().String(), c.Local.Port(), c.Local.Addr().String(),
		)
	} else {
		filter = fmt.Sprintf(
			"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			c.Local.Port(), c.Local.Addr().String(), c.Remote.Port(), c.Remote.Addr().String(),
		)
	}

	// todo: divert support ctxPeriod option
	if c.raw, err = divert.Open(filter, divert.Network, cfg.DivertPriorty, 0); err != nil {
		c.Close()
		return err
	}

	if c.ipstack, err = ipstack.New(
		c.Local.Addr(), c.Remote.Addr(),
		header.TCPProtocolNumber,
		cfg.IPStack.Unmarshal(),
	); err != nil {
		return err
	}

	return nil
}

func (c *Conn) Read(ctx context.Context, pkt *packet.Packet) (err error) {
	b := pkt.Bytes()
	n, err := c.raw.RecvCtx(ctx, b[:cap(b)], nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return errorx.ShortBuff(n)
		}
		return err
	}

	pkt.SetData(n)
	hdr, err := iconn.ValidComplete(pkt.Bytes())
	if err != nil {
		return err
	}
	if debug.Debug() {
		test.ValidIP(test.T(), pkt.Bytes())
	}
	pkt.SetHead(pkt.Head() + int(hdr))
	return nil
}

func (c *Conn) Write(ctx context.Context, p *packet.Packet) (err error) {
	c.ipstack.AttachOutbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Bytes())
	}

	// todo: ctx
	_, err = c.raw.Send(p.Bytes(), outboundAddr)
	return err
}

func (c *Conn) Inject(ctx context.Context, p *packet.Packet) (err error) {
	c.ipstack.AttachInbound(p)

	if debug.Debug() {
		test.ValidIP(test.T(), p.Bytes())
	}

	_, err = c.raw.Send(p.Bytes(), c.injectAddr)
	return err
}

func (c *Conn) Close() error {
	var err error
	if c.closeFn != nil {
		if e := c.closeFn(c.ID); e != nil {
			err = e
		}
	}
	if c.tcp != 0 {
		if e := windows.Close(c.tcp); e != nil {
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

func (c *Conn) LocalAddr() netip.AddrPort  { return c.Local }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.Remote }
