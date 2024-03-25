package tcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/rsocket/conn"
	"github.com/lysShub/rsocket/helper/ipstack"
	"github.com/lysShub/rsocket/packet"
	"github.com/lysShub/rsocket/test"
	"github.com/lysShub/rsocket/test/debug"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listenerDivert struct {

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

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []closedTCPInfo
	closedConnsMu sync.RWMutex
}

var _ conn.Listener = (*listenerDivert)(nil)

func ListenDivert(locAddr netip.AddrPort, opts ...conn.Option) (*listenerDivert, error) {
	var l = &listenerDivert{
		cfg:   conn.Options(opts...),
		conns: make(map[netip.AddrPort]uint32, 16),
	}

	var err error
	l.tcp, l.addr, err = conn.BindLocal(locAddr, l.cfg.UsedPort)
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

func (l *listenerDivert) Close() error {
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

func (l *listenerDivert) Addr() netip.AddrPort { return l.addr }

func (l *listenerDivert) Accept() (conn.RawConn, error) {
	var min, max = tcpSynSizeRange(l.addr.Addr().Is4())
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
			conn := newConnectDivert(
				l.addr, raddr, isn,
				addr.Loopback(), int(addr.Network().IfIdx),
				l.deleteConn,
			)

			return conn, conn.init(l.cfg.DivertPriorty+1, l.cfg.CompleteCheck, l.cfg.IPStack)
			// todo: inject P1
		}
	}
}

func (l *listenerDivert) purgeDeleted() {
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

func (l *listenerDivert) deleteConn(raddr netip.AddrPort, isn uint32) error {
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

type connDivert struct {
	laddr, raddr netip.AddrPort
	isn          uint32
	loopback     bool
	complete     bool

	tcp windows.Handle

	raw *divert.Handle

	injectAddr *divert.Address

	ipstack *ipstack.IPStack

	closeFn closeCallback
}

var outboundAddr = func() *divert.Address {
	addr := &divert.Address{}
	addr.SetOutbound(true)
	// addr.Flags.IPChecksum() // todo: set false
	return addr
}()

var _ conn.RawConn = (*connDivert)(nil)

func ConnectDivert(laddr, raddr netip.AddrPort, opts ...conn.Option) (*connDivert, error) {
	cfg := conn.Options(opts...)

	tcp, laddr, err := conn.BindLocal(laddr, cfg.UsedPort)
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
	c := newConnectDivert(
		laddr, raddr, 0,
		loopback, idx, nil,
	)
	c.tcp = tcp

	return c, c.init(cfg.DivertPriorty, cfg.CompleteCheck, cfg.IPStack)
}

func newConnectDivert(laddr, raddr netip.AddrPort, isn uint32, loopback bool, ifIdx int, closeCall closeCallback) *connDivert {

	var conn = &connDivert{
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

func (c *connDivert) init(priority int16, complete bool, ipOpts *ipstack.Configs) (err error) {
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

	// todo: divert support ctxPeriod option
	if c.raw, err = divert.Open(filter, divert.Network, priority, 0); err != nil {
		c.Close()
		return err
	}

	if c.ipstack, err = ipstack.New(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber,
		ipOpts.Unmarshal(),
	); err != nil {
		return err
	}

	c.complete = complete
	return nil
}

func (c *connDivert) Read(ctx context.Context, p *packet.Packet) (err error) {
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

func (c *connDivert) Write(ctx context.Context, p *packet.Packet) (err error) {
	c.ipstack.AttachOutbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}

	// todo: ctx
	_, err = c.raw.Send(p.Data(), outboundAddr)
	return err
}

func (c *connDivert) Inject(ctx context.Context, p *packet.Packet) (err error) {
	c.ipstack.AttachInbound(p)

	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}

	_, err = c.raw.Send(p.Data(), c.injectAddr)
	return err
}

func (c *connDivert) Close() error {
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

func (c *connDivert) LocalAddr() netip.AddrPort  { return c.laddr }
func (c *connDivert) RemoteAddr() netip.AddrPort { return c.raddr }
