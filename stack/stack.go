package stack

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

type TCPStack interface {

	/*
						对接ip-conn
						    |
		   SendSeg  ==> RecvRaw
		   RecvSeg  <== SendRaw
	*/

	SendSeg(seg []byte) (n int, err error)
	RecvSeg(seg []byte) (n int, err error)

	RecvRaw() (h header.TCP, err error)
	SendRaw(h header.TCP) (n int, err error)
}

type TCPStackGvisor struct {
	stack *stack.Stack

	ip  *networkProtocol
	tcp *tcpWrapProtocol

	mu          sync.RWMutex
	state       state
	initTrigger *sync.Cond
	initErr     error

	lport, rport uint16
}

type state uint32

const (
	none state = iota
	initing
	inited
)

func (s *state) cas(old, new state) bool {
	return atomic.CompareAndSwapUint32((*uint32)(s), uint32(old), uint32(new))
}
func (s *state) inited() bool {
	return atomic.LoadUint32((*uint32)(s)) == uint32(inited)
}

var constAddr = tcpip.AddrFrom4([4]byte{192, 168, 0, 1})

const constNic tcpip.NICID = 123

func NewTCPStackGvisor(lport, rport, mtu uint16) (*TCPStackGvisor, error) {
	var s = &TCPStackGvisor{
		ip:  NewNetwork(),
		tcp: NewTCPProtocolWrap(), // stack.New will call Number function

		lport: lport,
		rport: rport,
	}
	s.initTrigger = sync.NewCond(&s.mu)

	s.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{s.NetworkProtocolFactory},
		TransportProtocols: []stack.TransportProtocolFactory{s.TransportProtocolFactory},
		HandleLocal:        true,
	})
	if err := s.stack.CreateNIC(constNic, NewLink(int(mtu))); err != nil {
		return nil, errors.New(err.String())
	}
	if err := s.stack.AddProtocolAddress(constNic, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: constAddr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}
	s.stack.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	}})

	return s, s.tcp.init(s.stack)
}

func (s *TCPStackGvisor) NetworkProtocolFactory(*stack.Stack) stack.NetworkProtocol {
	return s.ip
}

func (s *TCPStackGvisor) TransportProtocolFactory(*stack.Stack) stack.TransportProtocol {
	return s.tcp
}

func (s *TCPStackGvisor) SendSeg(seg []byte) (n int, err error) {
	if !s.state.inited() { // todo: 需要三种状态
		s.mu.Lock()
		s.initTrigger.Wait()
		s.mu.Unlock()
	}

	// todo: 参考gonet

	n64, e := s.tcp.ep.Write(bytes.NewReader(seg), tcpip.WriteOptions{})
	if e != nil {
		return 0, errors.New(e.String())
	}

	return int(n64), nil
}

func (s *TCPStackGvisor) RecvSeg(seg []byte) (n int, err error) {
	if !s.state.inited() {
		s.mu.Lock()
		s.initTrigger.Wait()
		s.mu.Unlock()
	}

	// todo: 参考gonet

	w := tcpip.SliceWriter(seg)

	res, e := s.tcp.ep.Read(&w, tcpip.ReadOptions{})
	if _, ok := e.(*tcpip.ErrWouldBlock); ok {

		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		s.tcp.wq.EventRegister(&waitEntry)
		defer s.tcp.wq.EventUnregister(&waitEntry)

		for {
			res, e = s.tcp.ep.Read(&w, tcpip.ReadOptions{})
			if _, ok := e.(*tcpip.ErrWouldBlock); !ok {
				break
			}
			<-notifyCh
		}
	}

	if _, ok := e.(*tcpip.ErrClosedForReceive); ok {
		return 0, io.EOF
	} else if e != nil {
		return 0, errors.New(e.String())
	}
	return res.Count, nil
}

func (s *TCPStackGvisor) RecvRaw() (h header.TCP, err error) {
	if s.state.cas(none, initing) {
		// connect
		if s.initErr = s.initBase(); s.initErr != nil {
			return nil, s.initErr
		}
		go s.initConnect()
	}

	b := <-s.ip.ep.rawCh

	return header.TCP(b), nil
}

func (s *TCPStackGvisor) SendRaw(h header.TCP) (n int, err error) {
	if s.state.cas(none, initing) {
		// accept
		if s.initErr = s.initBase(); s.initErr != nil {
			return 0, s.initErr
		}
		go s.initAccept()
	}

	// notice:
	//    这个 PacketBufferPtr 太不友好了

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:            buffer.MakeWithData(h[h.DataOffset():]),
		ReserveHeaderBytes: header.IPv4MinimumSize + int(h.DataOffset()),
	})
	pkb.NICID = constNic
	pkb.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkb.TransportProtocolNumber = header.TCPProtocolNumber
	ipHdr := header.IPv4(pkb.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHdr.SetSourceAddress(constAddr)
	ipHdr.SetDestinationAddress(constAddr)
	tcpHdr := pkb.TransportHeader().Push(int(h.DataOffset()))
	copy(tcpHdr, h)

	s.tcp.transportProtocol.QueuePacket(s.tcp.ep, stack.TransportEndpointID{}, pkb)

	return len(h), nil
}

func (s *TCPStackGvisor) SetSockOpt(opt tcpip.SettableSocketOption) error {
	e := s.tcp.ep.SetSockOpt(opt)
	if e != nil {
		return &net.OpError{
			Op:  "setopt",
			Net: "tcp",
			Err: errors.New(e.String()),
		}
	} else {
		return nil
	}
}

func (s *TCPStackGvisor) initBase() error {
	_, err := s.tcp.NewEndpoint(s.ip.Number(), &waiter.Queue{})
	if err != nil {
		return &net.OpError{
			Op:  "new endpoint",
			Net: "tcp",
			Err: errors.New(err.String()),
		}
	}

	err = s.tcp.ep.Bind(tcpip.FullAddress{
		NIC:  constNic,
		Addr: constAddr,
		Port: s.lport,
	})
	if err != nil {
		return &net.OpError{
			Op:  "bind",
			Net: "tcp",
			Err: errors.New(err.String()),
		}
	}
	return nil
}

func (s *TCPStackGvisor) initAccept() {
	if err := s.tcp.ep.Listen(1); err != nil {
		s.initErr = &net.OpError{
			Op:  "listen",
			Err: errors.New(err.String()),
		}
		return
	}

	var (
		err tcpip.Error
		ep  tcpip.Endpoint
		wq  *waiter.Queue

		raddr = &tcpip.FullAddress{
			NIC:  constNic,
			Addr: constAddr,
			Port: s.rport,
		}
	)

	ep, wq, err = s.tcp.ep.Accept(raddr)
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {

		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		s.tcp.wq.EventRegister(&waitEntry)
		defer s.tcp.wq.EventUnregister(&waitEntry)

		<-notifyCh

		ep, wq, err = s.tcp.ep.Accept(raddr)
	}
	if err != nil {
		s.initErr = &net.OpError{
			Op:  "accept",
			Net: "tcp",
			Err: errors.New(err.String()),
		}
		return
	}

	// todo: maybe always self
	epPtr1, wqPtr1 := uintptr(unsafe.Pointer(&s.tcp.ep)), uintptr(unsafe.Pointer(&s.tcp.wq))
	epPtr2, wqPtr2 := uintptr(unsafe.Pointer(&ep)), uintptr(unsafe.Pointer(&wq))

	fmt.Println(epPtr1, epPtr2)
	fmt.Println(wqPtr1, wqPtr2)

	s.state.cas(initing, inited)
	s.initTrigger.Broadcast()
}

func (s *TCPStackGvisor) initConnect() {
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	s.tcp.wq.EventRegister(&waitEntry)
	defer s.tcp.wq.EventUnregister(&waitEntry)

	e := s.tcp.ep.Connect(tcpip.FullAddress{
		NIC:  constNic,
		Addr: constAddr,
		Port: s.rport,
	})
	if _, ok := e.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		e = s.tcp.ep.LastError()
	}
	if e != nil {
		s.tcp.ep.Close()
		s.initErr = &net.OpError{
			Op:  "connect",
			Net: "tcp",
			Err: errors.New(e.String()),
		}
		return
	}

	s.state.cas(initing, inited)
	s.initTrigger.Broadcast()
}
