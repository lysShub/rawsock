package tcp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_RawConn_BPF_Filter(t *testing.T) {
	var (
		cPort = 1234
		sPort = 80
	)

	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: locIP, Port: sPort})
		require.NoError(t, err)
		defer l.Close()
		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			// go io.Copy(conn, conn)

			go func() {
				defer conn.Close()
				var b = make([]byte, 1536)
				for {
					n, err := conn.Read(b)
					require.NoError(t, err)
					_, err = conn.Write(b[:n])
					require.NoError(t, err)
				}
			}()
		}
	}()

	raw, err := NewRawWithBPF(&net.TCPAddr{IP: locIP, Port: cPort}, &net.TCPAddr{IP: locIP, Port: sPort})
	require.NoError(t, err)
	defer raw.Close()

	// noise
	go func() {
		conn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: locIP})
		require.NoError(t, err)
		defer conn.Close()

		for {
			{
				b := []byte{
					0, 81, 4, 210, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
				}
				_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 10)
			}
			{
				b := []byte{
					0, 80, 4, 211, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
				}
				_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 10)
			}
			{
				b := []byte{
					0, 81, 4, 211, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
				}
				_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 10)
			}
		}
	}()

	//
	go func() {
		time.Sleep(time.Second)

		b := []byte{
			4, 210, 0, 80, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
		}
		_, err = raw.Write(b)
		require.NoError(t, err)
	}()

	for i := 0; i < 2; i++ {
		var b = make([]byte, 1536)
		n, err := raw.Read(b)
		require.NoError(t, err)
		ipHdr := header.IPv4(b[:n])
		tcpHdr := header.TCP(ipHdr.Payload())

		require.Equal(t, uint16(80), tcpHdr.SourcePort())
		require.Equal(t, uint16(1234), tcpHdr.DestinationPort())
	}
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
