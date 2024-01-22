package tcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func ListenWithDivert(dll *divert.DivertDLL, locAddr netip.AddrPort) (*listenerDivert, error) {
	var l = &listenerDivert{
		conns: make(map[netip.AddrPort]struct{}, 16),
	}

	var err error
	l.tcp, l.addr, err = listenLocal(locAddr)
	if err != nil {
		l.Close()
		return nil, err
	}

	// ref: https://reqrypt.org/windivert-doc.html#divert_open
	// note that Windows considers any packet originating from, and destined to, the current machine to be a
	// loopback packet, so loopback packets are not limited to localhost addresses. Note that WinDivert considers
	// loopback packets to be outbound only, and will not capture loopback packets on the inbound path.
	//
	// so, this filter will not capture loopback packet.
	var filter = fmt.Sprintf(
		"tcp and !loopback and localPort=%d and localAddr=%s",
		l.addr.Port(), l.addr.Addr().String(),
	)

	if l.raw, err = dll.Open(filter, divert.LAYER_SOCKET, 0, divert.READ_ONLY); err != nil {
		l.Close()
		return nil, err
	}

	return l, err
}

type listenerDivert struct {
	addr netip.AddrPort
	tcp  *net.TCPListener
	raw  *divert.Divert

	dll *divert.DivertDLL

	conns   map[netip.AddrPort]struct{}
	connsMu sync.RWMutex
}

func (l *listenerDivert) Close() error {
	var errs []error

	if l.tcp != nil {
		errs = append(errs, l.tcp.Close())
	}
	if l.raw != nil {
		errs = append(errs, l.raw.Close())
	}
	return errors.Join(errs...)
}

func (l *listenerDivert) Accept() (relraw.RawConn, error) {
	for {
		_, addr, err := l.raw.Recv(nil)
		if err != nil {
			return nil, err
		} else if addr.Event != divert.SOCKET_ACCEPT {
			continue
		}

		s := addr.Socket()

		raddr := netip.AddrPortFrom(s.RemoteAddr(), s.RemotePort)

		l.connsMu.RLock()
		_, ok := l.conns[raddr]
		l.connsMu.RUnlock()

		if ok {
			continue
		} else {
			// todo: 要删除这个， 用回调函数吧
			l.connsMu.Lock()
			l.conns[raddr] = struct{}{}
			l.connsMu.Unlock()

			var conn = &connDivert{
				laddr:   l.addr,
				raddr:   raddr,
				closeFn: l.deleteConn,
			}

			return conn, conn.init(l.dll)
		}
	}
}

func (l *listenerDivert) deleteConn(raddr netip.AddrPort) error {
	if l == nil {
		return nil
	}
	l.connsMu.Lock()
	delete(l.conns, raddr)
	l.connsMu.Unlock()
	return nil
}

type connDivert struct {
	laddr, raddr netip.AddrPort
	out, in      *relraw.IPStack

	tcp *net.TCPListener

	raw *divert.Divert

	closeFn CloseCallback
}

var _ relraw.RawConn = (*connDivert)(nil)

var (
	outboundAddr = &divert.Address{Layer: divert.LAYER_NETWORK, Event: divert.NETWORK_PACKET}
	inboundAddr  = &divert.Address{Layer: divert.LAYER_NETWORK, Event: divert.NETWORK_PACKET}
)

func init() {
	outboundAddr.SetOutbound(true)
	inboundAddr.SetOutbound(false)
}

func ConnectWithDivert(dll *divert.DivertDLL, laddr, raddr netip.AddrPort) (*connDivert, error) {
	var r = &connDivert{
		raddr: raddr,
	}
	var err error

	// listenLocal, forbid other process use this port
	r.tcp, r.laddr, err = listenLocal(laddr)
	if err != nil {
		r.Close()
		return nil, err
	}
	if !internal.ValideConnectAddrs(r.laddr.Addr(), r.raddr.Addr()) {
		r.Close()
		return nil, &net.OpError{
			Op:     "listen",
			Source: r.LocalAddr(),
			Addr:   r.RemoteAddr(),
			Err:    fmt.Errorf("invalid address"),
		}
	}

	return r, r.init(dll)
}

func (r *connDivert) init(dll *divert.DivertDLL) (err error) {
	r.out, err = relraw.NewIPStack(r.laddr.Addr(), r.raddr.Addr())
	if err != nil {
		r.Close()
		return err
	}
	r.in, err = relraw.NewIPStack(r.raddr.Addr(), r.laddr.Addr())
	if err != nil {
		r.Close()
		return err
	}

	var filter = fmt.Sprintf(
		"tcp and localPort=%d and localAddr=%s and remotePort=%d and remoteAddr=%s",
		r.laddr.Port(), r.laddr.Addr().String(), r.raddr.Port(), r.raddr.Addr().String(),
	)

	if r.raw, err = dll.Open(filter, divert.LAYER_NETWORK, 0, 0); err != nil {
		r.Close()
		return err
	}

	return nil
}

func (r *connDivert) Read(b []byte) (n int, err error) {
	n, _, err = r.raw.Recv(b)
	return n, err
}
func (r *connDivert) Write(b []byte) (n int, err error) {
	i := r.out.AttachHeaderSize()
	ip := make([]byte, i+len(b))
	copy(ip[i:], b)
	r.out.AttachHeader(ip, header.TCPProtocolNumber)

	return r.raw.Send(ip, outboundAddr)
}

func (r *connDivert) WriteReservedIPHeader(ip []byte) (n int, err error) {
	r.out.AttachHeader(ip, header.TCPProtocolNumber)
	return r.raw.Send(ip, outboundAddr)
}

func (r *connDivert) Inject(b []byte) (n int, err error) {
	i := r.in.AttachHeaderSize()
	ip := make([]byte, i+len(b))
	copy(ip[i:], b)
	r.in.AttachHeader(ip, header.TCPProtocolNumber)

	return r.raw.Send(ip, inboundAddr)
}

func (r *connDivert) InjectReservedIPHeader(ip []byte) (n int, err error) {
	r.in.AttachHeader(ip, header.TCPProtocolNumber)
	return r.raw.Send(ip, inboundAddr)
}

func (c *connDivert) Close() error {
	var errs []error
	if c.closeFn != nil {
		errs = append(errs, c.closeFn(c.raddr))
	}
	if c.tcp != nil {
		errs = append(errs, c.tcp.Close())
	}
	if c.raw != nil {
		errs = append(errs, c.raw.Close())
	}
	return errors.Join(errs...)
}

func (r *connDivert) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: r.laddr.Addr().AsSlice(), Port: int(r.laddr.Port())}
}
func (r *connDivert) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: r.raddr.Addr().AsSlice(), Port: int(r.raddr.Port())}
}
func (r *connDivert) LocalAddrAddrPort() netip.AddrPort  { return r.laddr }
func (r *connDivert) RemoteAddrAddrPort() netip.AddrPort { return r.raddr }
