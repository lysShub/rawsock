package relraw

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_ReservedIPheader(t *testing.T) {

	var suits = []struct {
		src, dst netip.Addr
	}{
		// {
		// 	src: netip.MustParseAddr("127.0.0.1"),
		// 	dst: netip.MustParseAddr("8.8.8.8"),
		// },
		{
			src: netip.MustParseAddr("3ffe:ffff:fe00:0001:0000:0000:0000:0001"),
			dst: netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
		},
	}

	for _, suit := range suits {
		s := NewIPStack(
			suit.src, suit.dst,
			header.TCPProtocolNumber,
			ReservedIPheader, UpdateChecksum,
		)

		var tcp = func() header.TCP {
			var b = header.TCP(make([]byte, 64))
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

		s.AttachOutbound(ip)

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
