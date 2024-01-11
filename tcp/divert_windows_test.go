package tcp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/go-divert/embed"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

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

var dll, loadErr = divert.LoadDivert(embed.DLL64, embed.Sys64)

func init() {
	if loadErr != nil {
		panic(loadErr)
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
