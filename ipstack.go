package relraw

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type ipstack struct {
	hdr []byte

	ip4           bool
	ip4Id         atomic.Uint32
	ip4InitHdrsum uint16
	psoSum1       uint16
}

// NewIPStack simple ip state machine helper
func NewIPStack(laddr, raddr net.IP, proto tcpip.TransportProtocolNumber) (*ipstack, error) {
	switch proto {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
	default:
		return nil, fmt.Errorf("not support transport protocol number %d", proto)
	}

	var s = &ipstack{}
	s.ip4Id.Store(uint32(time.Now().UnixNano()))

	l, ok := netip.AddrFromSlice(laddr)
	if !ok {
		return nil, fmt.Errorf("invalid ip address %s", laddr.String())
	}
	r, ok := netip.AddrFromSlice(raddr)
	if !ok {
		return nil, fmt.Errorf("invalid ip address %s", raddr.String())
	}

	if l.Is4() {
		s.ip4 = true
		s.hdr = make([]byte, header.IPv4MinimumSize)

		header.IPv4(s.hdr).Encode(&header.IPv4Fields{
			TOS:            0,
			TotalLength:    0,
			ID:             0,
			Flags:          0,
			FragmentOffset: 0,
			TTL:            128,
			Protocol:       uint8(proto),
			Checksum:       0,
			SrcAddr:        tcpip.AddrFrom4(l.As4()),
			DstAddr:        tcpip.AddrFrom4(r.As4()),
			Options:        nil,
		})
		s.ip4InitHdrsum = checksum.Checksum(s.hdr, 0)
		s.psoSum1 = header.PseudoHeaderChecksum(
			proto,
			tcpip.AddrFrom4(l.As4()),
			tcpip.AddrFrom4(r.As4()),
			0,
		)
	} else {
		s.hdr = make([]byte, header.IPv6MinimumSize)

		header.IPv6(s.hdr).Encode(&header.IPv6Fields{
			TrafficClass:      0,
			FlowLabel:         0,
			PayloadLength:     0,
			TransportProtocol: tcpip.TransportProtocolNumber(proto),
			HopLimit:          128,
			SrcAddr:           tcpip.AddrFrom16(l.As16()),
			DstAddr:           tcpip.AddrFrom16(r.As16()),
		})
		s.psoSum1 = header.PseudoHeaderChecksum(
			proto,
			tcpip.AddrFrom16(l.As16()),
			tcpip.AddrFrom16(r.As16()),
			0,
		)
	}

	return s, nil
}

func (s *ipstack) Reserve() int {
	if s.ip4 {
		return header.IPv4MinimumSize
	} else {
		return header.IPv6MinimumSize
	}
}

// AttachHeader attach ip header to b[0:s.Reserve()], return
// pseudo header checksum
func (s *ipstack) AttachHeader(b []byte) (psoSum uint16) {
	copy(b[0:], s.hdr)

	if s.ip4 {
		id, n := uint16(s.ip4Id.Add(1)), uint16(len(b))
		header.IPv4(b).SetID(id)
		header.IPv4(b).SetTotalLength(n)
		header.IPv4(b).SetChecksum(^checksum.Combine(checksum.Combine(s.ip4InitHdrsum, id), n))
	} else {
		header.IPv6(b).SetPayloadLength(uint16(len(b) - s.Reserve()))
	}

	return checksum.Combine(s.psoSum1, uint16(len(b)-s.Reserve()))
}
