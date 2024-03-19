package tcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/config/ipstack"
	"github.com/lysShub/relraw/test"
	"github.com/lysShub/relraw/test/debug"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listener struct {

	/*
		Structure

			handle priority      	describe

			a          			  listener read new conn's first packet P1

			a+1        			  connection from Accept, read corresponding packet（not sniff）

			a+2 or MAX_PRIORITY   after a+1 open, inject P1 use this handle（ignore current, tcp will send muti SYN packet）
	*/
	// todo: inject P1

	addr netip.AddrPort
	cfg  *config.Config

	tcp windows.Handle

	raw *divert.Handle

	// priority int16

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []closedTCPInfo
	closedConnsMu sync.RWMutex
}

var _ relraw.Listener = (*listener)(nil)

func Listen(locAddr netip.AddrPort, opts ...relraw.Option) (*listener, error) {
	var l = &listener{
		cfg:   relraw.Options(opts...),
		conns: make(map[netip.AddrPort]uint32, 16),
	}

	var err error
	l.tcp, l.addr, err = internal.BindLocal(locAddr, l.cfg.UsedPort)
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
func Priority(p int16) relraw.Option {
	return func(c *config.Config) {
		c.DivertPriorty = p
	}
}

func (l *listener) Close() error {
	var err error
	if l.tcp != 0 {
		if e := windows.Close(l.tcp); e != nil {
			err = e
		}
	}
	if l.raw != nil {
		if e := l.raw.Close(); err != nil {
			err = e
		}
	}
	return err
}

func (l *listener) Addr() netip.AddrPort { return l.addr }

func (l *listener) Accept() (relraw.RawConn, error) {
	var min, max int = header.TCPMinimumSize, header.TCPHeaderMaximumSize
	if l.addr.Addr().Is4() {
		min += header.IPv4MinimumSize
		max += header.IPv4MaximumHeaderSize
	} else {
		min += header.IPv6MinimumSize
		max += header.IPv6MinimumSize
	}

	var addr divert.Address

	var b = make([]byte, max)
	for {
		n, err := l.raw.Recv(b[:max], &addr)
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
			raddr = netip.AddrPortFrom(netip.AddrFrom16(iphdr.SourceAddress().As16()), tcphdr.SourcePort())
			isn = tcphdr.SequenceNumber()
		default:
			return nil, fmt.Errorf("recv invalid ip packet: %s", hex.Dump(b[:n]))
		}

		newConn := false
		old, ok := l.conns[raddr]
		if !ok || (ok && old != isn) {
			l.conns[raddr] = isn
			newConn = true
		}

		if newConn {
			conn := newConnect(
				l.addr, raddr, isn,
				addr.Loopback(), int(addr.Network().IfIdx),
				l.deleteConn,
			)

			return conn, conn.init(l.cfg.DivertPriorty+1, l.cfg.CompleteCheck, l.cfg.IPStackCfg)
			// todo: inject P1
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

			l.closedConns = l.closedConns[:i]
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
	loopback     bool
	complete     bool

	tcp windows.Handle

	raw *divert.Handle

	injectAddr *divert.Address

	ipstack *relraw.IPStack

	closeFn closeCallback
}

var outboundAddr = func() *divert.Address {
	addr := &divert.Address{}
	addr.SetOutbound(true)
	// addr.Flags.IPChecksum() // todo: set false
	return addr
}()

var _ relraw.RawConn = (*conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...relraw.Option) (*conn, error) {
	cfg := relraw.Options(opts...)

	tcp, laddr, err := internal.BindLocal(laddr, cfg.UsedPort)
	if err != nil {
		return nil, err
	}

	addr, idx, err := divert.Gateway(raddr.Addr())
	if err != nil {
		return nil, err
	}
	if laddr.Addr().IsUnspecified() {
		laddr = netip.AddrPortFrom(addr, laddr.Port())
	} else {
		if laddr.Addr() != addr {
			err = errors.WithMessagef(
				windows.ERROR_NETWORK_UNREACHABLE,
				"%s -> %s", laddr.Addr().String(), raddr.Addr().String(),
			)
			return nil, err
		}
	}

	loopback := divert.Loopback(laddr.Addr(), raddr.Addr())
	c := newConnect(
		laddr, raddr, 0,
		loopback, idx, nil,
	)
	c.tcp = tcp

	return c, c.init(cfg.DivertPriorty, cfg.CompleteCheck, cfg.IPStackCfg)
}

func newConnect(laddr, raddr netip.AddrPort, isn uint32, loopback bool, ifIdx int, closeCall closeCallback) *conn {

	var conn = &conn{
		laddr:      laddr,
		raddr:      raddr,
		isn:        isn,
		loopback:   loopback,
		injectAddr: &divert.Address{},
		closeFn:    closeCall,
	}
	conn.injectAddr.SetOutbound(false)
	conn.injectAddr.Network().IfIdx = uint32(ifIdx)

	return conn
}

func (c *conn) init(priority int16, complete bool, ipOpts *ipstack.Options) (err error) {
	var filter string
	if c.loopback {
		// loopback recv as outbound packet, so raddr is localAddr laddr is remoteAddr
		filter = fmt.Sprintf(
			// outbound and
			"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			c.raddr.Port(), c.raddr.Addr().String(), c.laddr.Port(), c.laddr.Addr().String(),
		)
	} else {
		filter = fmt.Sprintf(
			"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			c.laddr.Port(), c.laddr.Addr().String(), c.raddr.Port(), c.raddr.Addr().String(),
		)
	}

	if c.raw, err = divert.Open(filter, divert.Network, priority, 0); err != nil {
		c.Close()
		return err
	}

	if c.ipstack, err = relraw.NewIPStack(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber,
		ipOpts.Unmarshal(),
	); err != nil {
		return err
	}

	c.complete = complete
	return nil
}

func (c *conn) Read(ip []byte) (n int, err error) {
	n, err = c.raw.Recv(ip, nil)
	if err == nil {
		c.ipstack.UpdateInbound(ip[:n])

		if debug.Debug() {
			test.ValidIP(test.T(), ip[:n])
		}
	}

	if c.complete && !internal.CompleteCheck(c.ipstack.IPv4(), ip) {
		return 0, errors.WithStack(io.ErrShortBuffer)
	}
	return n, err
}

func (c *conn) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	b := p.Data()
	n, err := c.raw.RecvCtx(ctx, b[:cap(b)], nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		return err
	}

	p.SetLen(n)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}

	switch header.IPVersion(b) {
	case 4:
		p.SetHead(p.Head() + int(header.IPv4(b).HeaderLength()))
	case 6:
		p.SetHead(p.Head() + header.IPv6MinimumSize)
	}
	return nil
}

func (c *conn) Write(ip []byte) (n int, err error) {
	if debug.Debug() {
		test.ValidIP(test.T(), ip)
	}

	c.ipstack.UpdateOutbound(ip)
	return c.raw.Send(ip, outboundAddr)
}

func (c *conn) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	c.ipstack.AttachOutbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}

	// todo: ctx
	_, err = c.raw.Send(p.Data(), outboundAddr)
	return err
}

func (c *conn) Inject(ip []byte) (err error) {
	if debug.Debug() {
		test.ValidIP(test.T(), ip)
	}

	c.ipstack.UpdateInbound(ip)
	_, err = c.raw.Send(ip, c.injectAddr)
	return err
}

func (c *conn) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	c.ipstack.AttachInbound(p)

	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}

	_, err = c.raw.Send(p.Data(), c.injectAddr)
	return err
}

func (c *conn) Close() error {
	var err error
	if c.closeFn != nil {
		if e := c.closeFn(c.raddr, c.isn); e != nil {
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

func (c *conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.laddr.Addr().AsSlice(), Port: int(c.laddr.Port())}
}
func (c *conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.raddr.Addr().AsSlice(), Port: int(c.raddr.Port())}
}
func (c *conn) LocalAddrPort() netip.AddrPort  { return c.laddr }
func (c *conn) RemoteAddrPort() netip.AddrPort { return c.raddr }
