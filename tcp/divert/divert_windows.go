package divert

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/tcp"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// set divert priority, for Listen will use p and p+1
func Priority(p int16) relraw.Opt {
	return func(c *config.Config) {
		c.DivertPriorty = p
	}
}

func Listen(locAddr netip.AddrPort, opts ...relraw.Opt) (*listener, error) {
	cfg := relraw.Options(opts...)

	var l = &listener{
		conns:    make(map[netip.AddrPort]struct{}, 16),
		b:        make([]byte, cfg.MTU),
		priority: cfg.DivertPriorty,
	}

	var err error
	l.tcp, l.addr, err = bindLocal(locAddr, cfg.UsedPort)
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

	if l.raw, err = divert.Open(filter, divert.NETWORK, l.priority, divert.READ_ONLY); err != nil {
		l.Close()
		return nil, err
	}

	return l, err
}

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
	tcp  windows.Handle
	raw  *divert.Divert

	priority int16

	conns map[netip.AddrPort]struct{}
	mu    sync.RWMutex

	b []byte
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

func (l *listener) Accept() (relraw.RawConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var addr divert.Address
	for {
		n, err := l.raw.Recv(l.b, &addr)
		if err != nil {
			return nil, err
		} else if n == 0 {
			return nil, fmt.Errorf("divert shutdown")
		}

		const (
			ip4tcp = header.TCPMinimumSize + header.IPv4MinimumSize
			ip6tcp = header.TCPMinimumSize + header.ICMPv6MinimumSize
		)

		var raddr netip.AddrPort

		ver := header.IPVersion(l.b)
		if ver == 4 && n >= ip4tcp {
			iphdr := header.IPv4(l.b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
		} else if ver == 6 && n >= ip6tcp {
			iphdr := header.IPv6(l.b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			raddr = netip.AddrPortFrom(netip.AddrFrom16(iphdr.SourceAddress().As16()), tcphdr.SourcePort())
		} else {
			return nil, fmt.Errorf("recv invalid ip packet: %s", hex.Dump(l.b[:n]))
		}

		l.mu.RLock()
		_, ok := l.conns[raddr]
		l.mu.RUnlock()
		if ok {
			continue // todo: inject
		} else {
			l.mu.Lock()
			l.conns[raddr] = struct{}{}
			l.mu.Unlock()

			var conn = &conn{
				laddr:      l.addr,
				raddr:      raddr,
				loopback:   addr.Loopback(),
				closeFn:    l.deleteConn,
				injectAddr: &divert.Address{},
			}
			conn.injectAddr.SetOutbound(false)
			conn.injectAddr.Network().IfIdx = addr.Network().IfIdx

			return conn, conn.init(l.priority + 1)
			// todo: inject P1
		}
	}
}

func (l *listener) deleteConn(raddr netip.AddrPort) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	delete(l.conns, raddr)
	l.mu.Unlock()
	return nil
}

type conn struct {
	laddr, raddr netip.AddrPort
	loopback     bool

	//
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

func Connect(laddr, raddr netip.AddrPort, opts ...relraw.Opt) (*conn, error) {
	cfg := relraw.Options(opts...)
	var r = &conn{
		raddr: raddr,
	}
	var err error

	// listenLocal, forbid other process use this port
	r.tcp, r.laddr, err = bindLocal(laddr, cfg.UsedPort)
	if err != nil {
		r.Close()
		return nil, err
	}

	r.injectAddr = &divert.Address{}
	r.injectAddr.SetOutbound(false)
	id, err := internal.GetNICIndex(laddr.Addr())
	if err != nil {
		return nil, err
	} else {
		r.injectAddr.Network().IfIdx = uint32(id)
	}

	r.loopback = internal.IsWindowLoopBack(r.laddr.Addr()) &&
		internal.IsWindowLoopBack(r.raddr.Addr())

	return r, r.init(cfg.DivertPriorty)
}

func (r *conn) init(priority int16) (err error) {
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

	r.ipstack = relraw.NewIPStack(
		r.laddr.Addr(), r.raddr.Addr(),
		header.TCPProtocolNumber,
		relraw.UpdateChecksum,
	)
	return nil
}

func bindLocal(laddr netip.AddrPort, usedPort bool) (windows.Handle, netip.AddrPort, error) {
	var sa windows.Sockaddr
	var af int = windows.AF_INET
	if laddr.Addr().Is4() {
		sa = &windows.SockaddrInet4{Addr: laddr.Addr().As4(), Port: int(laddr.Port())}
	} else {
		sa = &windows.SockaddrInet6{Addr: laddr.Addr().As16(), Port: int(laddr.Port())}
		af = windows.AF_INET6
	}

	fd, err := windows.Socket(af, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "socket",
			Err: err,
		}
	}

	if err := windows.Bind(fd, sa); err != nil {
		if err == windows.WSAEADDRINUSE && usedPort {
			return 0, laddr, nil
		}
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "bind",
			Err: err,
		}
	} else if usedPort {
		return windows.InvalidHandle, netip.AddrPort{}, config.ErrNotUsedPort(laddr.Port())
	}

	if laddr.Port() == 0 {
		rsa, err := windows.Getsockname(fd)
		if err != nil {
			return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
				Op:  "getsockname",
				Err: err,
			}
		}
		switch sa := rsa.(type) {
		case *windows.SockaddrInet4:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		case *windows.SockaddrInet6:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		default:
		}
	}
	return fd, laddr, nil
}

func (r *conn) Read(ip []byte) (n int, err error) {
	n, err = r.raw.Recv(ip, nil)
	return n, err
}

func (r *conn) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	b := p.Bytes()
	n, err := r.raw.RecvCtx(ctx, b[:cap(b)], nil)
	p.SetLen(n)
	return err
}

func (r *conn) Write(ip []byte) (n int, err error) {
	return r.raw.Send(ip, outboundAddr)
}

func (r *conn) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ipstack.AttachInbound(p)

	// todo: ctx
	_, err = r.raw.Send(p.Bytes(), outboundAddr)
	return err
}

func (r *conn) Inject(ip []byte) (err error) {
	_, err = r.raw.Send(ip, r.injectAddr)
	return err
}

func (r *conn) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ipstack.AttachInbound(p)
	_, err = r.raw.Send(p.Bytes(), r.injectAddr)
	return err
}

func (c *conn) Close() error {
	var errs []error
	if c.closeFn != nil {
		errs = append(errs, c.closeFn(c.raddr))
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
func (r *conn) LocalAddrAddrPort() netip.AddrPort  { return r.laddr }
func (r *conn) RemoteAddrAddrPort() netip.AddrPort { return r.raddr }
