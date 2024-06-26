//go:build linux
// +build linux

package eth

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/eth"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/netkit/route"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/helper"
	"github.com/lysShub/rawsock/helper/bind"
	"github.com/lysShub/rawsock/helper/bpf"
	"github.com/lysShub/rawsock/helper/ipstack"
	itcp "github.com/lysShub/rawsock/tcp/internal"
	"github.com/lysShub/rawsock/test"
	"github.com/mdlayher/arp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Listener struct {
	addr netip.AddrPort
	cfg  *rawsock.Config

	tcp *net.TCPListener

	raw *net.IPConn

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

	var err error
	l.tcp, l.addr, err = bind.ListenTCPLocal(laddr, l.cfg.UsedPort)
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
		bpf.FilterDstPortAndTCPSyn(l.addr.Port()),
	); err != nil {
		return nil, l.close(err)
	}

	return l, nil
}

func (l *Listener) close(cause error) error {
	return l.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)
		if l.raw != nil {
			errs = append(errs, l.raw.Close())
		}
		if l.tcp != nil {
			errs = append(errs, errors.WithStack(l.tcp.Close()))
		}
		return
	})
}

func (l *Listener) Addr() netip.AddrPort {
	return l.addr
}

// todo: not support private proto that not start with tcp SYN flag
func (l *Listener) Accept() (rawsock.RawConn, error) {
	var min, max = itcp.SizeRange(l.addr.Addr().Is4())

	var ip = make([]byte, max)
	for {
		n, err := l.raw.Read(ip[:max])
		if err != nil {
			return nil, l.close(err)
		} else if n < min {
			return nil, fmt.Errorf("recved invalid ip packet, bytes %d", n)
		}

		var id = itcp.ID{Local: l.addr}
		switch header.IPVersion(ip) {
		case 4:
			iphdr := header.IPv4(ip[:n])
			tcphdr := header.TCP(iphdr.Payload())
			id.Remote = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			id.ISN = tcphdr.SequenceNumber()
		case 6:
			iphdr := header.IPv6(ip[:n])
			tcphdr := header.TCP(iphdr.Payload())
			id.Remote = netip.AddrPortFrom(netip.AddrFrom4(iphdr.SourceAddress().As4()), tcphdr.SourcePort())
			id.ISN = tcphdr.SequenceNumber()
		default:
			continue
		}

		l.connsMu.RLock()
		_, has := l.conns[id]
		l.connsMu.RUnlock()

		if !has {
			l.connsMu.Lock()
			l.conns[id] = struct{}{}
			l.connsMu.Unlock()

			c := newConnect(id, l.deleteConn)
			if err := c.init(l.cfg); err != nil {
				return nil, errorx.WrapTemp(c.close(err))
			}
			return c, nil
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

func (l *Listener) Close() error {
	return l.close(nil)
}

type Conn struct {
	itcp.ID

	// todo: set buff 0
	tcp *net.TCPListener

	raw     *eth.ETHConn
	ipstack *ipstack.IPStack
	gateway net.HardwareAddr

	ctxPeriod time.Duration
	closeFn   itcp.CloseCallback

	closeErr errorx.CloseErr
}

var _ rawsock.RawConn = (*Conn)(nil)

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (*Conn, error) {
	cfg := rawsock.Options(opts...)
	var c = newConnect(itcp.ID{Local: laddr, Remote: raddr, ISN: 0}, nil)

	var err error
	c.tcp, c.Local, err = bind.ListenTCPLocal(laddr, cfg.UsedPort)
	if err != nil {
		return nil, c.close(err)
	}

	if err := c.init(cfg); err != nil {
		return nil, c.close(err)
	}
	return c, nil
}

func newConnect(id itcp.ID, closeCall itcp.CloseCallback) *Conn {
	return &Conn{
		ID:      id,
		closeFn: closeCall,
	}
}

func (c *Conn) init(cfg *rawsock.Config) (err error) {
	table, err := route.GetTable()
	if err != nil {
		return err
	}

	entry := table.Match(c.Remote.Addr())
	if !entry.Valid() {
		err = errors.WithMessagef(
			unix.EADDRNOTAVAIL, c.Remote.Addr().String(),
		)
		return errors.WithStack(err)
	}

	// get gateway mac address
	var ifi *net.Interface
	if !entry.Next.IsValid() {
		// is on loopback

		return errors.New("not support loopback connect")
		// lo, err := helper.LoopbackInterface()
		// if err != nil {
		// 	return err
		// }
		// ifi, err = net.InterfaceByName(lo)
		// if err != nil {
		// 	return errors.WithStack(err)
		// }
		// c.gateway = net.HardwareAddr(make([]byte, 6))
	} else {
		if debug.Debug() {
			require.Equal(test.T(), c.Local.Addr(), entry.Addr)
		}
		ifi, err = net.InterfaceByIndex(int(entry.Interface))
		if err != nil {
			return errors.WithStack(err)
		}

		// get gatway hardware address
		if client, err := arp.Dial(c.raw.Interface()); err != nil {
			return errors.WithStack(err)
		} else {
			defer client.Close()
			if err = client.SetDeadline(time.Now().Add(time.Second * 3)); err != nil {
				return errors.WithStack(err)
			}

			c.gateway, err = client.Resolve(entry.Next)
			if err != nil {
				return errors.WithStack(err)
			}
		}
	}

	if cfg.SetGRO {
		if err := bind.SetGRO(c.Local.Addr(), c.Remote.Addr(), false); err != nil {
			return err
		}
	}

	// create eth conn and set bpf filter
	c.raw, err = eth.Listen("eth:ip4", ifi)
	if err != nil {
		return err
	}
	if err := bpf.SetRawBPF(
		c.raw.SyscallConn(),
		bpf.FilterEndpoint(header.TCPProtocolNumber, c.Remote, c.Local),
	); err != nil {
		return err
	}

	if c.ipstack, err = ipstack.New(
		c.Local.Addr(), c.Remote.Addr(),
		header.TCPProtocolNumber, cfg.IPStack.Unmarshal(),
	); err != nil {
		return err
	}
	return nil
}

func (c *Conn) close(cause error) error {
	return c.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)
		if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		if c.tcp != nil {
			errs = append(errs, errors.WithStack(c.tcp.Close()))
		}
		if c.closeFn != nil {
			errs = append(errs, c.closeFn(c.ID))
		}
		return
	})
}

func (c *Conn) Read(pkt *packet.Packet) (err error) {
	n, _, err := c.raw.ReadFromETH(pkt.Bytes())
	if err != nil {
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

	_, err = c.raw.WriteToETH(pkt.Bytes(), c.gateway)
	return err
}

func (c *Conn) Inject(p *packet.Packet) (err error) {
	panic(errors.New("todo: not support, need test"))

	// c.ipstack.AttachInbound(p)
	// if debug.Debug() {
	// 	test.ValidIP(test.P(), p.Data())
	// }
	// // p.Attach(c.outEthdr[:])
	// _, err = c.raw.Write(p.Data())
	// return err
}
func (c *Conn) Raw() *eth.ETHConn { return c.raw }

func (c *Conn) LocalAddr() netip.AddrPort  { return c.Local }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.Remote }
func (c *Conn) Close() (err error)         { return c.close(nil) }
