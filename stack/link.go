package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type linkEndpoint struct {
	mtu int
}

func NewLink(mtu int) *linkEndpoint {
	return &linkEndpoint{mtu: mtu}
}

var _ stack.LinkEndpoint = (*linkEndpoint)(nil)

func (l *linkEndpoint) WritePackets(ps stack.PacketBufferList) (int, tcpip.Error) {
	panic("不应该调用link")
}
func (l *linkEndpoint) MTU() uint32                                  { return uint32(l.mtu) }
func (l *linkEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (l *linkEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (l *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 8 }
func (l *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher)    {}
func (l *linkEndpoint) IsAttached() bool                             { return false }
func (l *linkEndpoint) Wait()                                        {}
func (l *linkEndpoint) ARPHardwareType() header.ARPHardwareType      { return 0 }
func (l *linkEndpoint) AddHeader(stack.PacketBufferPtr)              {}
func (l *linkEndpoint) ParseHeader(stack.PacketBufferPtr) bool       { return false }
