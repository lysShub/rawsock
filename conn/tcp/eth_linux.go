package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/lysShub/rsocket/conn"
	"github.com/lysShub/rsocket/eth"
	"github.com/lysShub/rsocket/helper/bpf"
	"github.com/lysShub/rsocket/helper/ipstack"
	"github.com/lysShub/rsocket/packet"
	"github.com/lysShub/rsocket/route"
	"github.com/lysShub/rsocket/test"
	"github.com/lysShub/rsocket/test/debug"
	"github.com/mdlayher/arp"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listenerEth struct {
	addr netip.AddrPort
	cfg  *conn.Config

	tcp *net.TCPListener

	raw *net.IPConn

	// AddrPort:ISN
	conns map[netip.AddrPort]uint32

	closedConns   []closedTCPInfo
	closedConnsMu sync.RWMutex
}

var _ conn.Listener = (*listenerEth)(nil)

func ListenEth(laddr netip.AddrPort, opts ...conn.Option) (*listenerEth, error) {
	var l = &listenerEth{
		cfg:   conn.Options(opts...),
		conns: make(map[netip.AddrPort]uint32, 16),
	}

	var err error
	l.tcp, l.addr, err = conn.ListenLocal(laddr, l.cfg.UsedPort)
	if err != nil {
		l.Close()
		return nil, err
	}

	l.raw, err = net.ListenIP(
		"ip:tcp",
		&net.IPAddr{IP: l.addr.Addr().AsSlice(), Zone: laddr.Addr().Zone()},
	)
	if err != nil {
		l.Close()
		return nil, err
	}

	raw, err := l.raw.SyscallConn()
	if err != nil {
		l.Close()
		return nil, err
	}

	if err = bpf.SetRawBPF(
		raw,
		bpf.FilterDstPortAndSynFlag(l.addr.Port()),
	); err != nil {
		l.Close()
		return nil, err
	}

	return l, nil
}

func (l *listenerEth) Close() error {
	var err error
	if l.tcp != nil {
		if e := l.Close(); e != nil {
			err = e
		}
	}
	if l.raw != nil {
		if e := l.raw.Close(); e != nil {
			err = e
		}
	}
	return err
}

func (l *listenerEth) Addr() netip.AddrPort {
	return l.addr
}

// todo: not support private proto that not start with tcp SYN flag
func (l *listenerEth) Accept() (conn.RawConn, error) {
	var min, max = tcpSynSizeRange(l.addr.Addr().Is4())

	var b = make([]byte, max)
	for {
		n, err := l.raw.Read(b[:max])
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
			c := newConnectEth(
				l.addr, raddr, isn,
				l.deleteConn, l.cfg.CompleteCheck, l.cfg.CtxPeriod,
			)
			return c, c.init(l.cfg.IPStack)
		}
	}
}

func (l *listenerEth) purgeDeleted() {
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

func (l *listenerEth) deleteConn(raddr netip.AddrPort, isn uint32) error {
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

type connEth struct {
	laddr, raddr netip.AddrPort
	isn          uint32

	// todo: set buff 0
	tcp *net.TCPListener

	raw      *eth.ETHConn
	ipstack  *ipstack.IPStack
	outEthdr [header.EthernetMinimumSize]byte
	inEthdr  [header.EthernetMinimumSize]byte

	ctxPeriod     time.Duration
	completeCheck bool
	closeFn       closeCallback
}

var _ conn.RawConn = (*connEth)(nil)

func ConnectEth(laddr, raddr netip.AddrPort, opts ...conn.Option) (*connEth, error) {
	cfg := conn.Options(opts...)
	var c = newConnectEth(
		laddr, raddr, 0,
		nil, cfg.CompleteCheck, cfg.CtxPeriod,
	)

	var err error
	c.tcp, c.laddr, err = conn.ListenLocal(laddr, cfg.UsedPort)
	if err != nil {
		c.Close()
		return nil, err
	}

	return c, c.init(cfg.IPStack)
}

func newConnectEth(laddr, raddr netip.AddrPort, isn uint32, closeCall closeCallback, complete bool, ctxPeriod time.Duration) *connEth {
	return &connEth{
		laddr:         laddr,
		raddr:         raddr,
		isn:           isn,
		closeFn:       closeCall,
		completeCheck: complete,
		ctxPeriod:     ctxPeriod,
	}
}

func (c *connEth) init(ipcfg *ipstack.Configs) (err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	// create eth conn and set bpf filter
	var proto tcpip.NetworkProtocolNumber
	entry, err := route.GetBestInterface(c.raddr.Addr())
	if err != nil {
		return err
	}

	ifi, err := net.InterfaceByIndex(int(entry.Ifidx))
	if err != nil {
		return errors.WithStack(err)
	} else {
		if c.laddr.Addr().Is4() {
			proto = header.IPv4ProtocolNumber
			c.raw, err = eth.NewETHIdx("eth:ip4", ifi.Index)
			if err != nil {
				return err
			}
		} else {
			proto = header.IPv6ProtocolNumber
			c.raw, err = eth.NewETHIdx("eth:ip6", ifi.Index)
			if err != nil {
				return err
			}
		}
		if err := bpf.SetRawBPF(
			c.raw.SyscallConn(),
			bpf.FilterEndpoint(header.TCPProtocolNumber, c.laddr, c.raddr),
		); err != nil {
			return err
		}
	}

	//
	if c.ipstack, err = ipstack.New(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber, ipcfg.Unmarshal(),
	); err != nil {
		return err
	}
	if client, err := arp.Dial(ifi); err != nil {
		return errors.WithStack(err)
	} else {
		defer client.Close()
		if err = client.SetDeadline(time.Now().Add(time.Second * 3)); err != nil {
			return errors.WithStack(err)
		}

		dst, err := client.Resolve(c.raddr.Addr())
		if err != nil {
			return errors.WithStack(err)
		}

		header.Ethernet(c.outEthdr[:]).Encode(&header.EthernetFields{
			SrcAddr: tcpip.LinkAddress(c.raw.LocalAddr().(eth.ETHAddr)),
			DstAddr: tcpip.LinkAddress(dst),
			Type:    proto,
		})
		header.Ethernet(c.inEthdr[:]).Encode(&header.EthernetFields{
			SrcAddr: tcpip.LinkAddress(dst),
			DstAddr: tcpip.LinkAddress(c.raw.LocalAddr().(eth.ETHAddr)),
			Type:    proto,
		})
	}
	return nil
}

func (c *connEth) Close() (err error) {
	if c.tcp != nil {
		if e := c.tcp.Close(); err == nil {
			err = e
		}
	}
	if c.raw != nil {
		if e := c.raw.Close(); err == nil {
			err = e
		}
	}
	if c.closeFn != nil {
		if e := c.closeFn(c.raddr, c.isn); err == nil {
			err = e
		}
	}
	return err
}

func (c *connEth) Read(ctx context.Context, p *packet.Packet) (err error) {
	b := p.Data()
	b = b[:cap(b)]

	var n int
	for {
		err = c.raw.SetReadDeadline(time.Now().Add(c.ctxPeriod))
		if err != nil {
			return err
		}

		n, err = c.raw.Read(b)
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
	p.SetLen(n)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}
	switch header.IPVersion(b) {
	case 4:
		if !conn.CompleteCheck(true, p.Data()) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		p.SetHead(p.Head() + int(header.IPv4(b).HeaderLength()))
	case 6:
		if !conn.CompleteCheck(false, p.Data()) {
			return errors.WithStack(io.ErrShortBuffer)
		}
		p.SetHead(p.Head() + header.IPv6MinimumSize)
	}
	return nil
}

func (c *connEth) Write(ctx context.Context, p *packet.Packet) (err error) {
	c.ipstack.AttachOutbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}
	p.Attach(c.outEthdr[:])

	_, err = c.raw.Write(p.Data())
	return err
}

func (c *connEth) Inject(ctx context.Context, p *packet.Packet) (err error) {
	c.ipstack.AttachInbound(p)
	if debug.Debug() {
		test.ValidIP(test.T(), p.Data())
	}
	p.Attach(c.outEthdr[:])

	_, err = c.raw.Write(p.Data())
	return err
}

func (c *connEth) LocalAddr() netip.AddrPort {
	return c.laddr
}
func (c *connEth) RemoteAddr() netip.AddrPort {
	return c.raddr
}
