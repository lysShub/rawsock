package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type tcpProtocolWrap struct {
	transportProtocol

	ep transportEndpoint
	wq *waiter.Queue
}

type transportProtocol interface {
	stack.TransportProtocol

	QueuePacket(stack.TransportEndpoint, stack.TransportEndpointID, stack.PacketBufferPtr)
}

type transportEndpoint interface {
	stack.TransportEndpoint
	tcpip.Endpoint
}

func NewTCPProtocolWrap() *tcpProtocolWrap {
	return &tcpProtocolWrap{}
}

func (t *tcpProtocolWrap) init(s *stack.Stack) error {
	var ok bool
	t.transportProtocol, ok = (tcp.NewProtocol(s)).(transportProtocol)
	if !ok {
		return fmt.Errorf("invalid tcp protocol")
	}
	return nil
}

func (t *tcpProtocolWrap) NewEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	ep, err := t.transportProtocol.NewEndpoint(netProto, waitQueue)
	if err != nil {
		return nil, err
	}

	var ok bool
	t.ep, ok = ep.(transportEndpoint)
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	t.wq = waitQueue
	return t.ep, nil
}

func (t *tcpProtocolWrap) Number() tcpip.TransportProtocolNumber {
	return tcp.ProtocolNumber
}
