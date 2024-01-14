package tcp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_BPF_Filter(t *testing.T) {
	var (
		saddr = &net.TCPAddr{IP: locIP, Port: int(randPort())}
		caddr = &net.TCPAddr{IP: locIP, Port: int(randPort())}
	)

	// noise
	go func() {
		conn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: locIP})
		require.NoError(t, err)
		defer conn.Close()

		var noises = [][]byte{
			buildRawTCP(t, saddr, caddr, 128),

			buildRawTCP(t, &net.TCPAddr{IP: locIP, Port: int(randPort())}, saddr, 128),

			buildRawTCP(t, caddr, &net.TCPAddr{IP: locIP, Port: int(randPort())}, 128),

			buildRawTCP(t,
				&net.TCPAddr{IP: locIP, Port: int(randPort())},
				&net.TCPAddr{IP: locIP, Port: int(randPort())},
				128,
			),
		}

		for _, b := range noises {

			_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
			require.NoError(t, err)
			time.Sleep(time.Millisecond * 10)
		}
	}()
	time.Sleep(time.Second)

	raw, err := NewRawWithBPF(saddr, caddr) // todo:
	require.NoError(t, err)
	defer raw.Close()

	go func() {
		time.Sleep(time.Second)

		for i := 0; i < 3; i++ {
			b := buildRawTCP(t, caddr, saddr, 128)
			_, err = raw.Write(b)
			require.NoError(t, err)
			time.Sleep(time.Millisecond * 10)
		}
	}()

	for i := 0; i < 3; i++ {
		var b = make([]byte, 1536)
		n, err := raw.Read(b)
		require.NoError(t, err)
		iphdr := header.IPv4(b[:n])

		tcpHdr := header.TCP(iphdr.Payload())
		require.Equal(t, uint16(caddr.Port), tcpHdr.SourcePort())
		require.Equal(t, uint16(saddr.Port), tcpHdr.DestinationPort())
	}
}

func Test_RawConn_Dial_UsrStack_PingPong(t *testing.T) {
	var (
		cPort = int(randPort())
		sPort = int(randPort())
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
		raw, err := NewRawWithBPF(&net.TCPAddr{IP: locIP, Port: cPort}, &net.TCPAddr{IP: locIP, Port: sPort})
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
