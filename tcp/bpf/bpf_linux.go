//go:build linux
// +build linux

package bpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
	ibpf "github.com/lysShub/relraw/internal/bpf"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/config/ipstack"
	"github.com/lysShub/relraw/tcp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listener struct {
	addr netip.AddrPort
	cfg  *config.Config

	tcp *net.TCPListener

	raw             *net.IPConn
	minIPPacketSize int

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []internal.ClosedConnInfo
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
		return nil, errors.Join(err, l.Close())
	}

	l.raw, err = net.ListenIP(
		"ip:tcp",
		&net.IPAddr{IP: l.addr.Addr().AsSlice(), Zone: laddr.Addr().Zone()},
	)
	if err != nil {
		return nil, errors.Join(err, l.Close())
	}
	l.minIPPacketSize = internal.MinIPPacketSize(laddr.Addr(), header.TCPProtocolNumber)

	raw, err := l.raw.SyscallConn()
	if err != nil {
		return nil, errors.Join(err, l.Close())
	}

	if err = ibpf.SetBPF(
		raw,
		ibpf.FilterDstPortAndSynFlag(l.addr.Port()),
	); err != nil {
		return nil, err
	}

	return l, nil
}

func (l *listener) Close() error {
	var errs []error
	if l.tcp != nil {
		errs = append(errs, l.tcp.Close())
	}
	if l.raw != nil {
		errs = append(errs, l.raw.Close())
	}
	return errors.Join(errs...)
}

func (l *listener) Addr() netip.AddrPort {
	return l.addr
}

// todo: not support private proto that not start with tcp SYN flag
func (l *listener) Accept() (relraw.RawConn, error) {

	var b = make([]byte, l.cfg.MTU)
	for {
		b = b[:cap(b)]
		n, err := l.raw.Read(b)
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
			return c, c.init(l.cfg.IPStackCfg)
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
	tcp          *net.TCPListener

	raw *net.IPConn

	ipstack *relraw.IPStack

	ctxCancelDelay time.Duration

	closeFn tcp.CloseCallback
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
		return nil, errors.Join(err, c.Close())
	}

	return c, c.init(cfg.IPStackCfg)
}

func newConnect(laddr, raddr netip.AddrPort, isn uint32, closeCall tcp.CloseCallback, ctxDelay time.Duration) *conn {
	return &conn{
		laddr:          laddr,
		raddr:          raddr,
		isn:            isn,
		closeFn:        closeCall,
		ctxCancelDelay: ctxDelay,
	}
}

func (r *conn) init(ipCfg ipstack.Options) (err error) {
	r.raw, err = net.DialIP(
		"ip:tcp",
		&net.IPAddr{IP: r.laddr.Addr().AsSlice(), Zone: r.laddr.Addr().Zone()},
		&net.IPAddr{IP: r.raddr.Addr().AsSlice(), Zone: r.raddr.Addr().Zone()},
	)
	if err != nil {
		return errors.Join(err, r.Close())
	}

	raw, err := r.raw.SyscallConn()
	if err != nil {
		return errors.Join(err, r.Close())
	}

	// filter src/dst ports
	if err = ibpf.SetBPF(
		raw,
		ibpf.FilterSrcPortAndDstPort(r.raddr.Port(), r.laddr.Port()),
	); err != nil {
		return errors.Join(err, r.Close())
	}

	// read ip header
	e := raw.Control(func(fd uintptr) {
		err = unix.SetsockoptByte(int(fd), unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		if err != nil {
			return
		}
	})
	if err := errors.Join(err, e); err != nil {
		return errors.Join(err, r.Close())
	}

	r.ipstack, err = relraw.NewIPStack(
		r.laddr.Addr(), r.raddr.Addr(),
		header.TCPProtocolNumber,
		ipCfg.Unmarshal(),
	)
	return err
}

func (r *conn) Read(ip []byte) (n int, err error) {
	n, err = r.raw.Read(ip)
	if err == nil {
		r.ipstack.UpdateInbound(ip[:n])
	}
	return n, err
}

func (r *conn) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	b := p.Data()
	b = b[:cap(b)]

	var n int
	for {
		err = r.raw.SetReadDeadline(time.Now().Add(r.ctxCancelDelay))
		if err != nil {
			return err
		}

		n, err = r.raw.Read(b)
		if err == nil {
			break
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		} else {
			return err
		}
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
	return r.raw.Write(ip)
}

func (r *conn) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ipstack.AttachOutbound(p)
	_, err = r.raw.Write(p.Data())
	return err
}

func (r *conn) Inject(ip []byte) (err error) {
	r.ipstack.UpdateInbound(ip)
	_, err = r.raw.Write(ip)
	return err
}

func (r *conn) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ipstack.AttachInbound(p)

	_, err = r.raw.Write(p.Data())
	return err
}

func (r *conn) Close() error {
	var errs []error
	if r.closeFn != nil {
		errs = append(errs, r.closeFn(r.raddr, r.isn))
	}
	if r.tcp != nil {
		errs = append(errs, r.tcp.Close())
	}
	if r.raw != nil {
		errs = append(errs, r.raw.Close())
	}
	return errors.Join(errs...)
}

func (r *conn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   r.laddr.Addr().AsSlice(),
		Port: int(r.laddr.Port()),
		Zone: r.laddr.Addr().Zone(),
	}
}
func (r *conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   r.raddr.Addr().AsSlice(),
		Port: int(r.raddr.Port()),
		Zone: r.raddr.Addr().Zone(),
	}
}
func (r *conn) LocalAddrPort() netip.AddrPort {
	return r.laddr
}
func (r *conn) RemoteAddrPort() netip.AddrPort {
	return r.raddr
}
