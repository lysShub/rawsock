package relraw

import (
	"math/rand"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// build ip header
type IPStack struct {
	option    options
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber

	// init ip header
	in, out []byte

	// pseudo header checksum without totalLen
	psoSum1 uint16
}

type options struct {
	checksum       uint8
	calcIPChecksum bool
}

var defaultOption = options{
	checksum:       reCalcChecksum,
	calcIPChecksum: true,
}

const (
	_ = iota
	updateChecksumWithoutPseudo
	reCalcChecksum
	notCalcChecksum
)

// UpdateChecksum update transport layer checksum, the checksum without pseudo-checksum
func UpdateChecksum(o *options) {
	o.checksum = updateChecksumWithoutPseudo
}

// RecalcChecksum re-calculate transport layer checksum
func RecalcChecksum(o *options) {
	o.checksum = reCalcChecksum
}

// NotsetChecksum not set transport layer checksum, the value is 0
func NotsetChecksum(o *options) {
	o.checksum = notCalcChecksum
}

// NotsetIPChecksum not set ip4 checksum
func NotsetIPChecksum(o *options) {
	o.calcIPChecksum = false
}

func NewIPStack(laddr, raddr netip.Addr, proto tcpip.TransportProtocolNumber, opts ...func(*options)) *IPStack {
	var option = defaultOption
	for _, opt := range opts {
		opt(&option)
	}

	var s = &IPStack{
		option:    option,
		transport: proto,
	}

	if laddr.Is4() {
		s.network = header.IPv4ProtocolNumber
		s.in, s.psoSum1 = initHdr(raddr, laddr, proto)
		s.out, s.psoSum1 = initHdr(laddr, raddr, proto)
	} else {
		s.network = header.IPv6ProtocolNumber
		s.in, s.psoSum1 = initHdr6(raddr, laddr, proto)
		s.out, s.psoSum1 = initHdr6(laddr, raddr, proto)
	}
	return s
}

func initHdr(src, dst netip.Addr, proto tcpip.TransportProtocolNumber) ([]byte, uint16) {
	f := &header.IPv4Fields{
		TOS:            0,
		TotalLength:    0, // dynamic
		ID:             0, // dynamic
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       uint8(proto),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src.As4()),
		DstAddr:        tcpip.AddrFrom4(dst.As4()),
		Options:        nil,
	}

	b := header.IPv4(make([]byte, header.IPv4MinimumSize))
	b.Encode(f)
	return []byte(b), header.PseudoHeaderChecksum(proto, f.SrcAddr, f.DstAddr, 0)
}

func initHdr6(src, dst netip.Addr, proto tcpip.TransportProtocolNumber) ([]byte, uint16) {
	f := &header.IPv6Fields{
		TrafficClass:      0,
		FlowLabel:         0,
		PayloadLength:     0, // dynamic
		TransportProtocol: proto,
		HopLimit:          128,
		SrcAddr:           tcpip.AddrFrom16(src.As16()),
		DstAddr:           tcpip.AddrFrom16(dst.As16()),
	}

	b := header.IPv6(make([]byte, header.IPv6MinimumSize))
	b.Encode(f)
	return []byte(b), header.PseudoHeaderChecksum(proto, f.SrcAddr, f.DstAddr, 0)
}

func (i *IPStack) Size() int {
	if i.network == header.IPv4ProtocolNumber {
		return header.IPv4MinimumSize
	} else {
		return header.IPv6MinimumSize
	}
}

func (i *IPStack) AttachInbound(p *Packet) {
	p.Attach(i.in)
	i.attachAndUpdateTransportChecksum(p.Data())
}

func (i *IPStack) AttachOutbound(p *Packet) {
	p.Attach(i.out)
	i.attachAndUpdateTransportChecksum(p.Data())
}

func (i *IPStack) attachAndUpdateTransportChecksum(ip []byte) {
	psosum, p := i.attach(ip)

	switch i.transport {
	case header.TCPProtocolNumber:
		tcphdr := header.TCP(p)
		var sum uint16
		switch i.option.checksum {
		case updateChecksumWithoutPseudo:
			sum = ^tcphdr.Checksum()
		case reCalcChecksum:
			sum = checksum.Checksum(tcphdr, 0)
		case notCalcChecksum:
			sum = 0xffff
		default:
			panic("")
		}
		tcphdr.SetChecksum(^checksum.Combine(psosum, sum))
	case header.UDPProtocolNumber:
		udphdr := header.UDP(p)
		var sum uint16
		switch i.option.checksum {
		case updateChecksumWithoutPseudo:
			sum = ^udphdr.Checksum()
		case reCalcChecksum:
			sum = checksum.Checksum(udphdr, 0)
		case notCalcChecksum:
			sum = 0xffff
		default:
			panic("")
		}
		udphdr.SetChecksum(^checksum.Combine(psosum, sum))
	}
}

func (i *IPStack) attach(ip []byte) (uint16, []byte) {
	if i.network == header.IPv4ProtocolNumber {
		iphdr := header.IPv4(ip)
		iphdr.SetTotalLength(uint16(len(iphdr)))
		iphdr.SetID(uint16(rand.Uint32()))
		if i.option.calcIPChecksum {
			iphdr.SetChecksum(^iphdr.CalculateChecksum())
		}

		var psosum uint16
		switch i.option.checksum {
		case reCalcChecksum, updateChecksumWithoutPseudo:
			psosum = checksum.Combine(i.psoSum1, uint16(len(iphdr.Payload())))
		case notCalcChecksum:
		default:
			panic("")
		}
		return psosum, iphdr.Payload()
	} else {
		iphdr := header.IPv6(ip)
		n := uint16(len(ip) - header.IPv6MinimumSize)
		iphdr.SetPayloadLength(n)

		var psosum uint16
		switch i.option.checksum {
		case reCalcChecksum, updateChecksumWithoutPseudo:
			psosum = checksum.Combine(i.psoSum1, n)
		case notCalcChecksum:
		default:
			panic("")
		}
		return psosum, iphdr.Payload()
	}
}
