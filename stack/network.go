package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type networkProtocol struct {
	ep *networkEndpoint
}

func NewNetwork() *networkProtocol {
	return &networkProtocol{ep: &networkEndpoint{
		rawCh: make(chan []byte, 4),
	}}
}

var _ stack.NetworkProtocol = (*networkProtocol)(nil)

func (p *networkProtocol) NewEndpoint(nic stack.NetworkInterface, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	p.ep.AddressableEndpointState.Init(p.ep, stack.AddressableEndpointStateOptions{HiddenWhileDisabled: false})

	return p.ep
}

func (p *networkProtocol) Number() tcpip.NetworkProtocolNumber              { return ipv4.ProtocolNumber }
func (p *networkProtocol) MinimumPacketSize() int                           { return 0 }
func (p *networkProtocol) ParseAddresses(b []byte) (src, dst tcpip.Address) { return }
func (p *networkProtocol) SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	return nil
}
func (p *networkProtocol) Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error { return nil }
func (p *networkProtocol) Close()                                                        {}
func (p *networkProtocol) Wait()                                                         {}
func (p *networkProtocol) Parse(pkt stack.PacketBufferPtr) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	return
}

type networkEndpoint struct {
	stack.AddressableEndpointState

	rawCh chan []byte
}

var _ stack.NetworkEndpoint = (*networkEndpoint)(nil)
var _ stack.AddressableEndpoint = (*networkEndpoint)(nil)

func (e *networkEndpoint) WritePacket(r *stack.Route, params stack.NetworkHeaderParams, pkt stack.PacketBufferPtr) tcpip.Error {
	ss := pkt.AsSlices()
	for _, s := range ss {
		tmp := make([]byte, len(s), cap(s))
		copy(tmp, s)

		e.rawCh <- tmp
	}
	return nil
}
func (e *networkEndpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt stack.PacketBufferPtr) tcpip.Error {
	for _, s := range pkt.AsSlices() {
		fmt.Println("outbind raw", s)
	}
	return nil
}

func (e *networkEndpoint) Enable() (err tcpip.Error)                              { return }
func (e *networkEndpoint) Enabled() (ok bool)                                     { return }
func (e *networkEndpoint) Disable()                                               {}
func (e *networkEndpoint) DefaultTTL() (ttl uint8)                                { return }
func (e *networkEndpoint) MTU() (mtu uint32)                                      { return }
func (e *networkEndpoint) MaxHeaderLength() (n uint16)                            { return }
func (e *networkEndpoint) HandlePacket(pkt stack.PacketBufferPtr)                 {}
func (e *networkEndpoint) Close()                                                 {}
func (e *networkEndpoint) NetworkProtocolNumber() (p tcpip.NetworkProtocolNumber) { return }
func (e *networkEndpoint) Stats() (s stack.NetworkEndpointStats)                  { return }
