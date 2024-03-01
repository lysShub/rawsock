package divert

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/config/ipstack"
	"github.com/lysShub/relraw/tcp"
	pkge "github.com/pkg/errors"
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

	raw             *divert.Divert
	minIPPacketSize int

	// priority int16

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []internal.ClosedConnInfo
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

	if l.raw, err = divert.Open(filter, divert.NETWORK, l.cfg.DivertPriorty, divert.READ_ONLY); err != nil {
		l.Close()
		return nil, err
	}
	l.minIPPacketSize = internal.MinIPPacketSize(l.addr.Addr(), header.TCPProtocolNumber)
	return l, err
}

// set divert priority, for Listen will use p and p+1
func Priority(p int16) relraw.Option {
	return func(c *config.Config) {
		c.DivertPriorty = p
	}
}

func (l *listener) Close() error {
	var errs []error

	if l.tcp != 0 {
		errs = append(errs, windows.Close(l.tcp))
	}
	if l.raw != nil {
		errs = append(errs, l.raw.Close())
	}
	return errors.Join(errs...)
}

func (l *listener) Addr() netip.AddrPort { return l.addr }

func (l *listener) Accept() (relraw.RawConn, error) {
	var addr divert.Address

	var b = make([]byte, l.cfg.MTU)
	for {
		b = b[:cap(b)]
		n, err := l.raw.Recv(b, &addr)
		if err != nil {
			return nil, err
		} else if n < l.minIPPacketSize {
			return nil, fmt.Errorf("recved invalid ip packet, bytes %d", n)
		}
		l.purgeOne()

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

			return conn, conn.init(l.cfg.DivertPriorty+1, l.cfg.IPStackCfg)
			// todo: inject P1
		}
	}
}

func (l *listener) purgeOne() {
	l.closedConnsMu.Lock()
	defer l.closedConnsMu.Unlock()

	if n := len(l.closedConns); n > 0 {
		i := n - 1
		c := l.closedConns[i]

		if time.Since(c.DeleteAt) > time.Minute {
			isn, ok := l.conns[c.Raddr]
			if ok && isn == c.ISN {
				delete(l.conns, c.Raddr)
			}

			l.closedConns = l.closedConns[:n-1]
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
		internal.ClosedConnInfo{
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

	tcp windows.Handle

	raw *divert.Divert

	injectAddr *divert.Address

	ipstack *relraw.IPStack

	closeFn tcp.CloseCallback
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
			err = pkge.WithMessagef(
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

	return c, c.init(cfg.DivertPriorty, cfg.IPStackCfg)
}

func newConnect(laddr, raddr netip.AddrPort, isn uint32, loopback bool, ifIdx int, closeCall tcp.CloseCallback) *conn {

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

func (r *conn) init(priority int16, ipOpts ipstack.Options) (err error) {
	var filter string
	if r.loopback {
		// loopback recv as outbound packet, so raddr is localAddr laddr is remoteAddr
		filter = fmt.Sprintf(
			// outbound and
			"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			r.raddr.Port(), r.raddr.Addr().String(), r.laddr.Port(), r.laddr.Addr().String(),
		)
	} else {
		filter = fmt.Sprintf(
			"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
			r.laddr.Port(), r.laddr.Addr().String(), r.raddr.Port(), r.raddr.Addr().String(),
		)
	}

	if r.raw, err = divert.Open(filter, divert.NETWORK, priority, 0); err != nil {
		r.Close()
		return err
	}

	r.ipstack, err = relraw.NewIPStack(
		r.laddr.Addr(), r.raddr.Addr(),
		header.TCPProtocolNumber,
		ipOpts.Unmarshal(),
	)
	return err
}

func (r *conn) Read(ip []byte) (n int, err error) {
	n, err = r.raw.Recv(ip, nil)
	if err == nil {
		r.ipstack.UpdateInbound(ip[:n])
	}
	return n, err
}

func (r *conn) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	b := p.Data()
	n, err := r.raw.RecvCtx(ctx, b[:cap(b)], nil)
	if err != nil {
		return err
	}

	p.SetLen(n)
	switch header.IPVersion(b) {
	case 4:
		p.SetHead(p.Head() + int(header.IPv4(b).HeaderLength()))
	case 6:
		p.SetHead(p.Head() + header.IPv6MinimumSize)
	}
	return nil
}

func (r *conn) Write(ip []byte) (n int, err error) {
	r.ipstack.UpdateOutbound(ip)
	return r.raw.Send(ip, outboundAddr)
}

func (r *conn) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ipstack.AttachOutbound(p)

	// todo: ctx
	_, err = r.raw.Send(p.Data(), outboundAddr)
	return err
}

func (r *conn) Inject(ip []byte) (err error) {
	r.ipstack.UpdateInbound(ip)
	_, err = r.raw.Send(ip, r.injectAddr)
	return err
}

func (r *conn) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ipstack.AttachInbound(p)
	_, err = r.raw.Send(p.Data(), r.injectAddr)
	return err
}

func (c *conn) Close() error {
	var errs []error
	if c.closeFn != nil {
		errs = append(errs, c.closeFn(c.raddr, c.isn))
	}
	if c.tcp != 0 {
		errs = append(errs, windows.Close(c.tcp))
	}
	if c.raw != nil {
		errs = append(errs, c.raw.Close())
	}
	return errors.Join(errs...)
}

func (r *conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: r.laddr.Addr().AsSlice(), Port: int(r.laddr.Port())}
}
func (r *conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: r.raddr.Addr().AsSlice(), Port: int(r.raddr.Port())}
}
func (r *conn) LocalAddrPort() netip.AddrPort  { return r.laddr }
func (r *conn) RemoteAddrPort() netip.AddrPort { return r.raddr }
