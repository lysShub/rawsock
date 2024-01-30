package relraw

import (
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

type IPStack struct {
	laddr, raddr  tcpip.Address
	addrsChecksum uint16

	networkProto tcpip.NetworkProtocolNumber
	ip4IdRander  *rand.Rand
}

// NewIPStack simple ip state machine helper
func NewIPStack(laddr, raddr netip.Addr) (*IPStack, error) {
	var s = &IPStack{}

	if !laddr.IsValid() {
		return nil, fmt.Errorf("invalid ip address %s", laddr.String())
	} else {
		s.laddr = tcpip.AddrFromSlice(laddr.AsSlice())
	}
	if !raddr.IsValid() {
		return nil, fmt.Errorf("invalid ip address %s", raddr.String())
	} else {
		s.raddr = tcpip.AddrFromSlice(raddr.AsSlice())
	}

	if laddr.Is4() && raddr.Is4() {
		s.networkProto = ipv4.ProtocolNumber
	} else if laddr.Is6() && raddr.Is6() {
		s.networkProto = ipv6.ProtocolNumber
	} else {
		return s, fmt.Errorf("invalid ip address from %s to %s", laddr, raddr)
	}
	s.addrsChecksum = addrsChecksum(s.laddr, s.raddr)
	s.ip4IdRander = rand.New(rand.NewSource(time.Now().UnixNano()))

	return s, nil
}

func addrsChecksum(addr1, addr2 tcpip.Address) uint16 {
	return checksum.Combine(
		checksum.Checksum(addr1.AsSlice(), 0),
		checksum.Checksum(addr2.AsSlice(), 0),
	)
}

func (s *IPStack) AttachHeaderSize() int {
	switch s.networkProto {
	case header.IPv4ProtocolNumber:
		return header.IPv4MinimumSize
	case header.IPv6ProtocolNumber:
		return header.IPv6MinimumSize
	default:
		return 0
	}
}

func (s *IPStack) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return s.networkProto
}

func (s *IPStack) AttachHeader(ip []byte, proto tcpip.TransportProtocolNumber) (psoSum uint16) {
	var payloadLen uint16
	switch s.networkProto {
	case header.IPv4ProtocolNumber:
		iphdr := header.IPv4(ip)

		iphdr.Encode(&header.IPv4Fields{
			TOS:            0,
			TotalLength:    uint16(len(iphdr)),
			ID:             uint16(s.ip4IdRander.Uint32()),
			Flags:          0,
			FragmentOffset: 0,
			TTL:            128,
			Protocol:       uint8(proto),
			Checksum:       0,
			SrcAddr:        s.laddr,
			DstAddr:        s.raddr,
			Options:        nil,
		})
		iphdr.SetChecksum(^checksum.Checksum(iphdr[:12], s.addrsChecksum))

		payloadLen = iphdr.PayloadLength()
	case header.IPv6ProtocolNumber:
		iphdr := header.IPv6(ip)

		iphdr.Encode(&header.IPv6Fields{
			TrafficClass:      0,
			FlowLabel:         0,
			PayloadLength:     uint16(len(ip) - header.IPv6MinimumSize),
			TransportProtocol: proto,
			HopLimit:          128,
			SrcAddr:           s.laddr,
			DstAddr:           s.raddr,
		})

		payloadLen = iphdr.PayloadLength()
	default:
		return 0
	}

	psoSum = checksum.Combine(s.addrsChecksum, payloadLen)
	switch proto {
	case header.TCPProtocolNumber:
		return checksum.Combine(psoSum, uint16(header.TCPProtocolNumber))
	case header.UDPProtocolNumber:
		return checksum.Combine(psoSum, uint16(header.UDPProtocolNumber))
	default:
		return 0
	}
}

func (s *IPStack) UpdateHeader(ip []byte) []byte {
	var (
		attached       bool
		payload        []byte
		oldsum, newsum uint16
		proto          tcpip.TransportProtocolNumber
	)
	switch header.IPVersion(ip) {
	case 4:
		proto = header.IPv4(ip).TransportProtocol()

		if s.networkProto != header.IPv4ProtocolNumber {
			attached = true
			oldsum = header.PseudoHeaderChecksum(
				header.IPv4(ip).TransportProtocol(),
				header.IPv4(ip).SourceAddress(),
				header.IPv4(ip).DestinationAddress(),
				header.IPv4(ip).PayloadLength(),
			)

			ip = setPrefixBytes(ip, int(header.IPv4(ip).HeaderLength()), s.AttachHeaderSize())
			newsum = s.AttachHeader(ip, proto)
		}
	case 6:
		proto = header.IPv6(ip).TransportProtocol()

		if s.networkProto != header.IPv6ProtocolNumber {
			attached = true
			oldsum = header.PseudoHeaderChecksum(
				header.IPv6(ip).TransportProtocol(),
				header.IPv6(ip).SourceAddress(),
				header.IPv6(ip).DestinationAddress(),
				header.IPv6(ip).PayloadLength(),
			)

			ip = setPrefixBytes(ip, header.IPv6MinimumSize, s.AttachHeaderSize())
			newsum = s.AttachHeader(ip, proto)
		}
	default:
		return ip
	}

	switch s.networkProto {
	case header.IPv4ProtocolNumber:
		payload = header.IPv4(ip).Payload()
		if !attached {
			oldsum = addrsChecksum(
				header.IPv4(ip).SourceAddress(),
				header.IPv4(ip).DestinationAddress(),
			)
			header.IPv4(ip).SetSourceAddressWithChecksumUpdate(s.laddr)
			header.IPv4(ip).SetDestinationAddressWithChecksumUpdate(s.raddr)
			newsum = s.addrsChecksum
		}
	case header.IPv6ProtocolNumber:
		payload = header.IPv6(ip).Payload()
		if !attached {
			oldsum = addrsChecksum(
				header.IPv6(ip).SourceAddress(),
				header.IPv6(ip).DestinationAddress(),
			)
			header.IPv6(ip).SetSourceAddress(s.laddr)
			header.IPv6(ip).SetDestinationAddress(s.raddr)
			newsum = s.addrsChecksum
		}
	default:
		return ip
	}

	switch proto {
	case header.TCPProtocolNumber:
		tcphdr := header.TCP(payload)
		sum := checksum.Combine(checksum.Combine(^tcphdr.Checksum(), ^oldsum), newsum)
		tcphdr.SetChecksum(^sum)
	case header.UDPProtocolNumber:
		udphdr := header.UDP(payload)
		sum := checksum.Combine(checksum.Combine(^udphdr.Checksum(), ^oldsum), newsum)
		udphdr.SetChecksum(^sum)
	default:
	}

	return ip
}

func setPrefixBytes(b []byte, act, exp int) []byte {
	if act > exp {
		return b[act-exp:]
	} else {
		b = append(b[:exp], b[act:]...)
		return b
	}
}

type IPStack2 struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber

	up, down []byte

	// pseudo header checksum without totalLen
	psoSum1 uint16
}

func NewIPStack2(laddr, raddr netip.Addr, proto tcpip.TransportProtocolNumber) *IPStack2 {
	var s = &IPStack2{transport: proto}

	if laddr.Is4() {
		s.network = header.IPv4ProtocolNumber
		s.up, s.psoSum1 = initHdr(laddr, raddr, proto)
		s.down, s.psoSum1 = initHdr(raddr, laddr, proto)
	} else {
		s.network = header.IPv6ProtocolNumber
		s.up, s.psoSum1 = initHdr6(laddr, raddr, proto)
		s.down, s.psoSum1 = initHdr6(raddr, laddr, proto)
	}
	return s
}

func initHdr(laddr, raddr netip.Addr, proto tcpip.TransportProtocolNumber) ([]byte, uint16) {
	f := &header.IPv4Fields{
		TOS:            0,
		TotalLength:    0, // dynamic
		ID:             0, // dynamic
		Flags:          0,
		FragmentOffset: 0,
		TTL:            128,
		Protocol:       uint8(proto),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(laddr.As4()),
		DstAddr:        tcpip.AddrFrom4(raddr.As4()),
		Options:        nil,
	}

	b := header.IPv4(make([]byte, header.IPv4MinimumSize))
	b.Encode(f)
	return []byte(b), header.PseudoHeaderChecksum(proto, f.SrcAddr, f.DstAddr, 0)
}

func initHdr6(laddr, raddr netip.Addr, proto tcpip.TransportProtocolNumber) ([]byte, uint16) {
	f := &header.IPv6Fields{
		TrafficClass:      0,
		FlowLabel:         0,
		PayloadLength:     0, // dynamic
		TransportProtocol: proto,
		HopLimit:          128,
		SrcAddr:           tcpip.AddrFrom16(laddr.As16()),
		DstAddr:           tcpip.AddrFrom16(raddr.As16()),
	}

	b := header.IPv6(make([]byte, header.IPv6MinimumSize))
	b.Encode(f)
	return []byte(b), header.PseudoHeaderChecksum(proto, f.SrcAddr, f.DstAddr, 0)
}

func (i *IPStack2) AttachSize() int {
	if i.network == header.IPv4ProtocolNumber {
		return header.IPv4MinimumSize
	} else {
		return header.IPv6MinimumSize
	}
}

func (i *IPStack2) AttachUp(ip []byte) {
	copy(ip, i.up)
	i.attachAndUpdateTransportChecksum(ip)
}

func (i *IPStack2) AttachDown(ip []byte) {
	copy(ip, i.down)
	i.attachAndUpdateTransportChecksum(ip)
}

func (i *IPStack2) attachAndUpdateTransportChecksum(ip []byte) {
	psoSum, t := i.attach(ip)

	switch i.transport {
	case header.TCPProtocolNumber:
		tcphdr := header.TCP(t)
		ss := tcphdr.Checksum()
		sum := checksum.Combine(psoSum, ss)
		tcphdr.SetChecksum(^sum)
	case header.UDPProtocolNumber:
		udphdr := header.UDP(t)
		sum := checksum.Combine(psoSum, udphdr.Checksum())
		udphdr.SetChecksum(^sum)
	}
}

func (i *IPStack2) attach(ip []byte) (uint16, []byte) {
	if i.network == header.IPv4ProtocolNumber {
		iphdr := header.IPv4(ip)
		iphdr.SetTotalLength(uint16(len(iphdr)))
		iphdr.SetID(uint16(rand.Uint32()))
		psoSum := checksum.Combine(i.psoSum1, uint16(len(iphdr)-header.IPv4MinimumSize))
		return psoSum, iphdr.Payload()
	} else {
		iphdr := header.IPv6(ip)
		n := uint16(len(ip) - header.IPv6MinimumSize)
		iphdr.SetPayloadLength(n)
		return checksum.Combine(i.psoSum1, n), iphdr.Payload()
	}
}
