package tcp

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/go-divert/embed"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

var dll, loadErr = divert.LoadDivert(embed.DLL64, embed.Sys64)

func init() {
	if loadErr != nil {
		panic(loadErr)
	}
}

func TestBindLocal(t *testing.T) {
	{
		fd, addr, err := bindLocal(nil)
		require.NotEqual(t, windows.InvalidHandle, fd)
		require.NotNil(t, addr)
		require.NotZero(t, addr.Port)
		require.NoError(t, err)
		require.NoError(t, windows.Close(fd))
	}

	{
		port := time.Now().UnixNano() % (0xffff - 0xff)
		if port < 1024 {
			port += 1024
		}

		fd, addr, err := bindLocal(&net.TCPAddr{Port: 12345})
		require.NoError(t, err)
		require.Equal(t, &net.TCPAddr{IP: []byte{0, 0, 0, 0}, Port: 12345}, addr)

		fd1, addr1, err1 := bindLocal(&net.TCPAddr{Port: 12345})
		require.Equal(t, windows.InvalidHandle, fd1)
		require.Nil(t, addr1)
		require.Error(t, err1)

		require.NoError(t, windows.Close(fd))
	}
}

func TestDivertAutoHandleDF(t *testing.T) {
	go func() {
		time.Sleep(time.Second)

		b := buildOutboundIP(t, 1536)
		addr := &divert.Address{Layer: divert.LAYER_NETWORK, Event: divert.NETWORK_PACKET}
		addr.SetOutbound(true)

		d, err := dll.Open("false", divert.LAYER_NETWORK, 1, divert.WRITE_ONLY)
		require.NoError(t, err)
		defer d.Close()
		_, err = d.Send(b, addr)
		require.NoError(t, err)
	}()

	filter := fmt.Sprintf(
		"!loopback and outbound and tcp and localAddr=%s and localPort=12345 and remoteAddr=8.8.8.8 and remotePort=19986",
		locIP,
	)

	d, err := dll.Open(filter, divert.LAYER_NETWORK, 0, divert.READ_ONLY)
	require.NoError(t, err)
	defer d.Close()

	var b = make([]byte, 1536)
	n, _, err := d.Recv(b)
	require.NoError(t, err)
	require.Equal(t, 1536, n)
}

func buildOutboundIP(t *testing.T, size int) []byte {
	var b = header.IPv4(make([]byte, size))
	b.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		ID:          uint16(time.Now().UnixNano()),
		Flags:       0,
		TTL:         64,
		Protocol:    uint8(tcp.ProtocolNumber),
		Checksum:    0,
		SrcAddr:     tcpip.AddrFromSlice(locIP),
		DstAddr:     tcpip.AddrFromSlice([]byte{8, 8, 8, 8}),
	})
	b.SetChecksum(^checksum.Checksum(b[:20], 0))
	require.True(t, b.IsChecksumValid())

	tcpHdr := header.TCP(b.Payload())
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    12345,
		DstPort:    19986,
		SeqNum:     1380 + 369874248,
		AckNum:     501 + 369874248,
		DataOffset: 20,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 83,
		Checksum:   0,
	})
	tcpHdr.SetChecksum(^checksum.Checksum(
		tcpHdr,
		header.PseudoHeaderChecksum(
			tcp.ProtocolNumber,
			b.SourceAddress(),
			b.DestinationAddress(),
			uint16(len(tcpHdr)),
		)),
	)
	require.True(t,
		tcpHdr.IsChecksumValid(
			b.SourceAddress(),
			b.DestinationAddress(),
			checksum.Checksum(tcpHdr.Payload(), 0),
			uint16(len(tcpHdr.Payload())),
		),
	)

	return b
}

func Test_RawConn_Dial_UsrStack_PingPong(t *testing.T) {
	var (
		cPort = 12345
		sPort = 8080
	)

	// server
	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: locIP, Port: sPort})
		require.NoError(t, err)
		defer l.Close()
		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// usr-stack with raw-conn
	var conn net.Conn
	{
		raw, err := NewRawWithDivert(
			&net.TCPAddr{IP: locIP, Port: cPort},
			&net.TCPAddr{IP: locIP, Port: sPort},
			dll,
		)
		require.NoError(t, err)
		defer raw.Close()
		conn = pingPongWithUserStackClient(t, raw)
	}

	// client
	_, err := conn.Write([]byte("hello"))
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, []byte("hello"), b[:n])
}
