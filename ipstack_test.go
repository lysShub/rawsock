package relraw

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestIPv4Stack(t *testing.T) {
	src, dst := net.IP{127, 0, 0, 1}, net.ParseIP("8.8.8.8")
	s, err := NewIPStack(src, dst, header.TCPProtocolNumber)
	require.NoError(t, err)

	var buildTCP = func(n int) []byte {
		var b = make([]byte, n)
		ts := uint32(time.Now().UnixMilli())
		header.TCP(b[s.Reserve():]).Encode(&header.TCPFields{
			SrcPort:    12345,
			DstPort:    19986,
			SeqNum:     1380 + ts,
			AckNum:     501 + ts,
			DataOffset: 20,
			Flags:      header.TCPFlagAck | header.TCPFlagPsh,
			WindowSize: 83,
			Checksum:   0,
		})
		return b
	}

	ns := []int{512, 80, 1380, 1420, 64, 1536}
	id := uint16(0)
	for i := 0; i < 64; i++ {
		b := buildTCP(ns[i%len(ns)])

		psoSum := s.AttachHeader(b)
		iphdr := header.IPv4(b)
		tcphdr := header.TCP(iphdr.Payload())

		tcphdr.SetChecksum(^checksum.Checksum(
			tcphdr,
			psoSum,
		))

		ok1 := iphdr.IsChecksumValid()
		require.True(t, ok1)

		ok2 := tcphdr.IsChecksumValid(
			tcpip.AddrFromSlice(src),
			tcpip.AddrFromSlice(dst),
			checksum.Checksum(tcphdr.Payload(), 0),
			uint16(len(tcphdr.Payload())),
		)
		require.True(t, ok2)

		if i > 0 {
			require.Equal(t, id+1, iphdr.ID())
		}
		id = iphdr.ID()
	}
}
