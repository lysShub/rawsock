package relraw

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func Test_AttachHeader(t *testing.T) {

	var suits = []struct {
		src, dst netip.Addr
		newErr   error
	}{
		{
			src:    netip.Addr{},
			dst:    netip.MustParseAddr("8.8.8.8"),
			newErr: fmt.Errorf("invalid ip address %s", netip.Addr{}),
		},
		{
			src:    netip.MustParseAddr("127.0.0.1"),
			dst:    netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			newErr: fmt.Errorf("invalid ip address from %s to %s", netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334")),
		},
		{
			src: netip.MustParseAddr("127.0.0.1"),
			dst: netip.MustParseAddr("8.8.8.8"),
		},
		{
			src: netip.MustParseAddr("3ffe:ffff:fe00:0001:0000:0000:0000:0001"),
			dst: netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
		},
	}

	for _, suit := range suits {

		s, err := NewIPStack(suit.src, suit.dst)
		require.Equal(t, suit.newErr, err)
		if err != nil {
			continue
		}

		for i := 0; i < 32; i++ {
			mtu := func() int {
				mtu := rand.Uint32()
				if mtu < header.IPv4MinimumSize {
					mtu += header.IPv4MinimumSize
				}
				return int(mtu)
			}()

			var proto tcpip.TransportProtocolNumber
			if mtu%2 == 0 {
				proto = tcp.ProtocolNumber
			} else {
				proto = udp.ProtocolNumber
			}

			b := make([]byte, mtu)

			psosum := s.AttachHeader(b, proto)

			switch s.NetworkProtocolNumber() {
			case header.IPv4ProtocolNumber:
				iphdr := header.IPv4(b)

				ok1 := iphdr.IsChecksumValid()
				require.True(t, ok1)

				ok2 := iphdr.IsValid(len(iphdr))
				require.True(t, ok2)

				require.Equal(t, header.PseudoHeaderChecksum(
					proto,
					tcpip.AddrFromSlice(suit.src.AsSlice()),
					tcpip.AddrFromSlice(suit.dst.AsSlice()),
					uint16(len(b)-header.IPv4MinimumSize),
				), psosum)

				ok3 := tcpip.AddrFromSlice(suit.src.AsSlice()).Equal(iphdr.SourceAddress())
				require.True(t, ok3)

				ok4 := tcpip.AddrFromSlice(suit.dst.AsSlice()).Equal(iphdr.DestinationAddress())
				require.True(t, ok4)

			case header.IPv6ProtocolNumber:
				iphdr := header.IPv6(b)

				ok1 := iphdr.IsValid(len(iphdr))
				require.True(t, ok1)

				ok3 := tcpip.AddrFromSlice(suit.src.AsSlice()).Equal(iphdr.SourceAddress())
				require.True(t, ok3)

				ok4 := tcpip.AddrFromSlice(suit.dst.AsSlice()).Equal(iphdr.DestinationAddress())
				require.True(t, ok4)
			default:
			}

		}
	}
}

func Test_AttachHeader2(t *testing.T) {

	var buildIP = func(network tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber) []byte {
		var (
			b            []byte
			payload      []byte
			psosum       uint16
			saddr, raddr tcpip.Address
		)

		switch network {
		case header.IPv4ProtocolNumber:
			s, err := NewIPStack(netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"))
			require.NoError(t, err)
			b = make([]byte, int(rand.Uint32()%2000)+s.AttachHeaderSize())

			psosum = s.AttachHeader(b, transport)
			payload = header.IPv4(b).Payload()
			saddr, raddr = header.IPv4(b).SourceAddress(), header.IPv4(b).DestinationAddress()
		case header.IPv6ProtocolNumber:
			s, err := NewIPStack(
				netip.MustParseAddr("3ffe:ffff:fe00:0001:0000:0000:0000:0001"),
				netip.MustParseAddr("3ffe:ffff:fe00:0002:0000:0000:0000:0002"),
			)
			require.NoError(t, err)
			b = make([]byte, int(rand.Uint32()%2000)+s.AttachHeaderSize())

			psosum = s.AttachHeader(b, transport)
			payload = header.IPv6(b).Payload()
			saddr, raddr = header.IPv6(b).SourceAddress(), header.IPv6(b).DestinationAddress()
		default:
		}

		switch transport {
		case header.TCPProtocolNumber:
			tcphdr := header.TCP(payload)
			tcphdr.Encode(&header.TCPFields{
				SrcPort:    12345,
				DstPort:    19986,
				SeqNum:     rand.Uint32(),
				AckNum:     rand.Uint32(),
				DataOffset: 20,
				Flags:      header.TCPFlagAck | header.TCPFlagPsh,
				WindowSize: 83,
				Checksum:   0,
			})
			tcphdr.SetChecksum(^checksum.Checksum(tcphdr, psosum))

			ok := tcphdr.IsChecksumValid(
				saddr, raddr,
				checksum.Checksum(tcphdr.Payload(), 0),
				uint16(len(tcphdr.Payload())),
			)
			require.True(t, ok)
		case header.UDPProtocolNumber:
			udphdr := header.UDP(payload)
			udphdr.Encode(&header.UDPFields{
				SrcPort:  12345,
				DstPort:  19986,
				Length:   uint16(len(udphdr)),
				Checksum: 0,
			})
			udphdr.SetChecksum(^checksum.Checksum(udphdr, psosum))

			ok := udphdr.IsChecksumValid(
				saddr, raddr,
				checksum.Checksum(udphdr.Payload(), 0),
			)
			require.True(t, ok)
		default:
		}

		return b
	}

	var suits = []struct {
		src, dst netip.Addr
	}{
		{
			src: netip.MustParseAddr("127.0.0.1"),
			dst: netip.MustParseAddr("8.8.8.8"),
		},
		// {
		// 	src:   netip.MustParseAddr("127.0.0.1"),
		// 	dst:   netip.MustParseAddr("8.8.8.8"),
		// 	proto: udp.ProtocolNumber,
		// },
	}

	var cases = []struct {
		network   tcpip.NetworkProtocolNumber
		transport tcpip.TransportProtocolNumber
	}{
		{
			header.IPv4ProtocolNumber, header.TCPProtocolNumber,
		},
		{
			header.IPv4ProtocolNumber, header.UDPProtocolNumber,
		},
		{
			header.IPv6ProtocolNumber, header.TCPProtocolNumber,
		},
		{
			header.IPv6ProtocolNumber, header.UDPProtocolNumber,
		},
	}

	for _, suit := range suits {
		for _, c := range cases {

			s, err := NewIPStack(suit.src, suit.dst)
			require.NoError(t, err)
			var b = buildIP(c.network, c.transport)

			b = s.UpdateHeader(b)

			var payload []byte
			if s.NetworkProtocolNumber() == ipv4.ProtocolNumber {
				iphdr := header.IPv4(b)

				ok1 := iphdr.IsChecksumValid()
				require.True(t, ok1)
				require.True(t, tcpip.AddrFromSlice(suit.src.AsSlice()).Equal(iphdr.SourceAddress()))
				require.True(t, tcpip.AddrFromSlice(suit.dst.AsSlice()).Equal(iphdr.DestinationAddress()))

				payload = iphdr.Payload()
			} else {
				iphdr := header.IPv6(b)

				require.True(t, tcpip.AddrFromSlice(suit.src.AsSlice()).Equal(iphdr.SourceAddress()))
				require.True(t, tcpip.AddrFromSlice(suit.dst.AsSlice()).Equal(iphdr.DestinationAddress()))

				payload = iphdr.Payload()
			}

			if c.transport == tcp.ProtocolNumber {
				tcphdr := header.TCP(payload)

				ok2 := tcphdr.IsChecksumValid(
					tcpip.AddrFromSlice(suit.src.AsSlice()),
					tcpip.AddrFromSlice(suit.dst.AsSlice()),
					checksum.Checksum(tcphdr.Payload(), 0),
					uint16(len(tcphdr.Payload())),
				)
				require.True(t, ok2)
			} else {
				udphdr := header.UDP(payload)

				ok2 := udphdr.IsChecksumValid(
					tcpip.AddrFromSlice(suit.src.AsSlice()),
					tcpip.AddrFromSlice(suit.dst.AsSlice()),
					checksum.Checksum(udphdr.Payload(), 0),
				)
				require.True(t, ok2)
			}
		}
	}
}

func TestSetPrefixBytes(t *testing.T) {
	var b = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	var relcopy = func(b []byte) []byte {
		r := make([]byte, len(b))
		copy(r, b)
		return r
	}

	for i := 0; i < 0xff; i++ {
		actLen, expLen := rand.Uint32()%10, rand.Uint32()%10

		b1 := setPrefixBytes(relcopy(b), int(actLen), int(expLen))

		e := relcopy(b[actLen:])

		require.Equal(t, b1[expLen:], e, fmt.Sprintf("act:%d exp:%d", actLen, expLen))
	}
}
