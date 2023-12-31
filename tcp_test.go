package raw

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// 需要在内部实现缓存
type TCPStack interface {

	/*
							对接ip-conn
								|
		   OutboundSeg ==> OutboundRaw
		   InboundSeg  <== InboundRaw
	*/

	SendRaw(h header.TCP) (n int, err error)
	RecvSeg(seg []byte) (n int, err error)

	SendSeg(seg []byte) (n int, err error)
	RecvRaw() (n header.TCP, err error)
}

func TestXxxx(t *testing.T) {
	g, err := NewTCPStackGvisor(2345, 80, 1500)
	require.NoError(t, err)

	// 上行
	go func() {
		for {
			tcp, err := g.RecvRaw()
			require.NoError(t, err)
			t.Log(tcp)

			g.SendRaw(tcp)
		}
	}()

	// 下行
	_, err = g.SendSeg([]byte("123"))
	require.NoError(t, err)

	time.Sleep(time.Hour)
}

type TCPStackGvisor struct {
	stack *stack.Stack
	link  *channel.Endpoint
	conn  net.Conn

	inited atomic.Bool

	// useless
	laddr, raddr tcpip.FullAddress
	err          error

	rawView *buffer.View
}

var _ TCPStack = (*TCPStackGvisor)(nil)

const (
	nicid tcpip.NICID = 11
)

func NewTCPStackGvisor(lport, rport, mtu uint16) (*TCPStackGvisor, error) {
	var s = &TCPStackGvisor{
		laddr: tcpip.FullAddress{
			NIC:  nicid,
			Addr: tcpip.AddrFromSlice([]byte{192, 168, 0, 1}),
			Port: lport,
		},
		raddr: tcpip.FullAddress{
			NIC:  nicid,
			Addr: tcpip.AddrFromSlice([]byte{192, 168, 0, 2}),
			Port: rport,
		},
	}

	s.stack = stack.New(stack.Options{
		// todo: link, network层是可以不需要的
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	s.link = channel.New(4, uint32(mtu), "")
	if err := s.stack.CreateNIC(nicid, s.link); err != nil {
		return nil, errors.New(err.String())
	}

	s.stack.AddProtocolAddress(nicid, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: s.laddr.Addr.WithPrefix(),
	}, stack.AddressProperties{})
	s.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicid}})

	return s, nil
}

func (s *TCPStackGvisor) SendRaw(h header.TCP) (int, error) {
	if s.inited.CompareAndSwap(false, true) {
		// accept
		if s.err != nil {
			return 0, s.err
		}
		go func(s *TCPStackGvisor) {
			l, err := gonet.ListenTCP(s.stack, s.laddr, ipv4.ProtocolNumber)
			if err != nil {
				s.err = err
				s.inited.Store(false)
			}

			s.conn, err = l.Accept()
			if err != nil {
				s.err = err
				s.inited.Store(false)
			}
		}(s)
	}

	var pkts stack.PacketBufferList
	pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(h)}))

	_, err := s.link.WritePackets(pkts)
	if err != nil {
		return 0, errors.New(err.String())
	}
	return 0, nil
}

func (s *TCPStackGvisor) RecvSeg(seg []byte) (n int, err error) {

	for s.conn == nil {
		time.Sleep(time.Millisecond * 100)
	}

	// todo: 并非真正的seg
	return s.conn.Read(seg)
}

func (s *TCPStackGvisor) SendSeg(seg []byte) (n int, err error) {
	if s.inited.CompareAndSwap(false, true) {
		// connect
		if s.err != nil {
			return 0, s.err
		}
		s.conn, s.err = gonet.DialTCPWithBind(context.Background(), s.stack, s.laddr, s.raddr, ipv4.ProtocolNumber)
		if s.err != nil {
			s.inited.Store(false)
			return 0, s.err
		}
	}

	return s.conn.Write(seg)
}

func (s *TCPStackGvisor) RecvRaw() (t header.TCP, err error) {
	if s.rawView == nil {
		p := s.link.ReadContext(context.Background())

		s.rawView = p.ToView()
	}

	ip := header.IPv4(s.rawView.AsSlice())
	t = header.TCP(ip[ip.HeaderLength():]) // maybe: panic

	s.rawView = s.rawView.Next()
	return t, s.err
}
