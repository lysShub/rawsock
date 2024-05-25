package divert

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/netkit/route"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/helper"
	"github.com/lysShub/rawsock/helper/bind"
	"github.com/lysShub/rawsock/helper/ipstack"
	itcp "github.com/lysShub/rawsock/tcp/internal"
	"github.com/lysShub/rawsock/test"
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
	cfg  *rawsock.Config

	tcp windows.Handle

	raw *divert.Handle

	// priority int16

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

	// usaully should listen on all nic, but we juse listen on default nic
	if laddr.Addr().IsUnspecified() {
		laddr = netip.AddrPortFrom(rawsock.LocalAddr(), laddr.Port())
	}

	var err error
	l.tcp, l.addr, err = bind.BindLocal(header.TCPProtocolNumber, laddr, l.cfg.UsedPort)
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
func Priority(p int16) rawsock.Option {
	return func(c *rawsock.Config) {
		c.DivertPriorty = p
	}
}

func (l *Listener) close(cause error) error {
	return l.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if l.raw != nil {
			errs = append(errs, l.raw.Close())
		}
		if l.tcp != 0 {
			errs = append(errs, errors.WithStack(windows.Close(l.tcp)))
		}
		return
	})
}

func (l *Listener) Addr() netip.AddrPort { return l.addr }

func (l *Listener) Accept() (rawsock.RawConn, error) {
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
			l.connsMu.Unlock()

			conn := newConnect(
				id,
				addr.Loopback(), int(addr.Network().IfIdx),
				l.deleteConn,
			)

			if err := conn.init(l.cfg); err != nil {
				return nil, conn.close(err)
			}
			return conn, nil
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

	closeFn  itcp.CloseCallback
	closeErr errorx.CloseErr
}

var outboundAddr = func() *divert.Address {
	addr := &divert.Address{}
	addr.SetOutbound(true)
	// addr.Flags.IPChecksum() // todo: set false
	return addr
}()

var _ rawsock.RawConn = (*Conn)(nil)

func (c *Conn) close(cause error) error {
	return c.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		if c.tcp != 0 {
			errs = append(errs, errors.WithStack(windows.Close(c.tcp)))
		}
		if c.closeFn != nil {
			errs = append(errs, c.closeFn(c.ID))
		}
		return
	})
}

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (*Conn, error) {
	cfg := rawsock.Options(opts...)

	table, err := route.GetTable()
	if err != nil {
		return nil, err
	}
	entry := table.Match(raddr.Addr())
	if !entry.Valid() {
		err = errors.WithMessagef(
			windows.ERROR_NETWORK_UNREACHABLE,
			"%s -> %s", laddr.Addr().String(), raddr.Addr().String(),
		)
		return nil, errors.WithStack(err)
	}

	if laddr.Addr().IsUnspecified() {
		laddr = netip.AddrPortFrom(entry.Addr, laddr.Port())
	} else {
		if laddr.Addr() != entry.Addr {
			err = errors.WithMessagef(
				windows.WSAEADDRNOTAVAIL, laddr.Addr().String(),
			)
			return nil, errors.WithStack(err)
		}
	}

	tcp, laddr, err := bind.BindLocal(header.TCPProtocolNumber, laddr, cfg.UsedPort)
	if err != nil {
		return nil, err
	}

	c := newConnect(
		itcp.ID{Local: laddr, Remote: raddr, ISN: 0},
		table.Loopback(raddr.Addr()), int(entry.Interface), nil,
	)
	c.tcp = tcp

	if err := c.init(cfg); err != nil {
		return nil, c.close(err)
	}
	return c, nil
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

func (c *Conn) init(cfg *rawsock.Config) (err error) {
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

func (c *Conn) Read(pkt *packet.Packet) (err error) {
	n, err := c.raw.Recv(pkt.Bytes(), nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return errorx.ShortBuff(-1, n)
		}
		return err
	}

	pkt.SetData(n)
	hdr, err := helper.IPCheck(pkt.Bytes())
	if err != nil {
		return err
	}
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	pkt.SetHead(pkt.Head() + int(hdr))
	return nil
}

func (c *Conn) Write(pkt *packet.Packet) (err error) {
	defer pkt.DetachN(c.ipstack.Size())
	c.ipstack.AttachOutbound(pkt)
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}

	_, err = c.raw.Send(pkt.Bytes(), outboundAddr)
	return err
}

func (c *Conn) Inject(pkt *packet.Packet) (err error) {
	defer pkt.DetachN(c.ipstack.Size())
	c.ipstack.AttachInbound(pkt)
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}

	_, err = c.raw.Send(pkt.Bytes(), c.injectAddr)
	return err
}

func (c *Conn) LocalAddr() netip.AddrPort  { return c.Local }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.Remote }
func (c *Conn) Close() error               { return c.close(nil) }
