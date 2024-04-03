package ipstack_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/lysShub/sockit/helper/ipstack"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var suits = []struct {
	src, dst netip.Addr
}{
	{
		src: netip.MustParseAddr("127.0.0.1"),
		dst: netip.MustParseAddr("8.8.8.8"),
	},
	{
		src: netip.MustParseAddr("3ffe:ffff:fe00:0001:0000:0000:0000:0001"),
		dst: netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
	},
}

func init() {
	for i := 0; i < 16; i++ {
		suits = append(suits, struct {
			src netip.Addr
			dst netip.Addr
		}{
			src: test.RandIP(), dst: test.RandIP(),
		})
	}
}

func Test_IP_Stack_TCP(t *testing.T) {

	for _, suit := range suits {
		for _, opts := range [][]ipstack.Option{
			{ipstack.UpdateChecksum},
			{ipstack.ReCalcChecksum},
		} {

			s, err := ipstack.New(
				suit.src, suit.dst,
				header.TCPProtocolNumber,
				opts...,
			)
			require.NoError(t, err)

			var tcp = func() header.TCP {
				var b = header.TCP(make([]byte, max(rand.Int()%1536, header.TCPMinimumSize)))
				b.Encode(&header.TCPFields{
					SrcPort:    uint16(rand.Uint32()),
					DstPort:    uint16(rand.Uint32()),
					SeqNum:     rand.Uint32(),
					AckNum:     rand.Uint32(),
					DataOffset: 20,
					Flags:      header.TCPFlagAck | header.TCPFlagPsh,
					WindowSize: uint16(rand.Uint32()),
					Checksum:   0,
				})
				b.SetChecksum(^checksum.Checksum(b, 0))
				return b
			}()

			ip := make([]byte, s.Size()+len(tcp))
			copy(ip[s.Size():], tcp)

			s.AttachOutbound(packet.ToPacket(s.Size(), ip))

			var network header.Network
			if suit.src.Is4() {
				network = header.IPv4(ip)
			} else {
				network = header.IPv6(ip)
			}

			tcp = header.TCP(network.Payload())
			require.Equal(t, suit.src.String(), network.SourceAddress().String())
			require.Equal(t, suit.dst.String(), network.DestinationAddress().String())
			ok := tcp.IsChecksumValid(
				network.SourceAddress(),
				network.DestinationAddress(),
				checksum.Checksum(tcp.Payload(), 0),
				uint16(len(tcp.Payload())),
			)

			require.True(t, ok)
		}

	}

}

func Test_IP_Stack_UDP(t *testing.T) {

	for _, suit := range suits {
		for i := 0; i < 2; i++ {

			var err error
			var s *ipstack.IPStack
			if i == 0 {
				s, err = ipstack.New(
					suit.src, suit.dst,
					header.UDPProtocolNumber,
					ipstack.UpdateChecksum,
				)
				require.NoError(t, err)
			} else {
				s, err = ipstack.New(
					suit.src, suit.dst,
					header.UDPProtocolNumber,
					ipstack.ReCalcChecksum,
				)
				require.NoError(t, err)
			}

			var udp = func() header.UDP {
				var b = header.UDP(make([]byte, max(rand.Int()%1536, header.UDPMinimumSize)))
				b.Encode(&header.UDPFields{
					SrcPort:  uint16(rand.Uint32()),
					DstPort:  uint16(rand.Uint32()),
					Length:   uint16(len(b)),
					Checksum: 0,
				})
				b.SetChecksum(^checksum.Checksum(b, 0))
				return b
			}()

			ip := make([]byte, s.Size()+len(udp))
			copy(ip[s.Size():], udp)

			s.AttachOutbound(packet.ToPacket(s.Size(), ip))

			var network header.Network
			if suit.src.Is4() {
				network = header.IPv4(ip)
			} else {
				network = header.IPv6(ip)
			}

			udp = header.UDP(network.Payload())
			require.Equal(t, suit.src.String(), network.SourceAddress().String())
			require.Equal(t, suit.dst.String(), network.DestinationAddress().String())
			ok := udp.IsChecksumValid(
				network.SourceAddress(),
				network.DestinationAddress(),
				checksum.Checksum(udp.Payload(), 0),
			)

			require.True(t, ok)

		}
	}

}
