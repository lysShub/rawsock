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
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var dll, loadErr = divert.LoadDivert(embed.DLL, embed.Sys)

func init() {
	if loadErr != nil {
		panic(loadErr)
	}
}

func Test_Bind_Local(t *testing.T) {
	{
		fd, addr, err := bindLocal(nil)
		require.NotEqual(t, windows.InvalidHandle, fd)
		require.NotNil(t, addr)
		require.NotZero(t, addr.Port)
		require.NoError(t, err)
		require.NoError(t, windows.Close(fd))
	}

	{
		port := randPort()

		fd, addr, err := bindLocal(&net.TCPAddr{Port: int(port)})
		require.NoError(t, err)
		require.Equal(t, &net.TCPAddr{IP: []byte{0, 0, 0, 0}, Port: int(port)}, addr)

		fd1, addr1, err1 := bindLocal(&net.TCPAddr{Port: int(port)})
		require.Equal(t, windows.InvalidHandle, fd1)
		require.Nil(t, addr1)
		require.Error(t, err1)

		require.NoError(t, windows.Close(fd))
	}
}

func Test_Divert_Filter(t *testing.T) {
	t.Skip() // todo:

	ips := []net.IP{
		locIP,
		net.ParseIP("127.0.0.1"),
		net.ParseIP("0.0.0.0"),
	}

	for _, ip := range ips {
		caddr := &net.TCPAddr{IP: ip, Port: int(randPort())}
		saddr := &net.TCPAddr{IP: ip, Port: int(randPort())}

		// server
		go func() {
			l, err := net.ListenTCP("tcp", saddr)
			require.NoError(t, err)
			defer l.Close()
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			conn.Close()
		}()

		// capture client's inboud packet
		go func() {
			filter := fmt.Sprintf("tcp and localPort=%d and remotePort=%d", saddr.Port, caddr.Port)

			d, err := dll.Open(filter, divert.LAYER_NETWORK, 0, divert.SNIFF)
			require.NoError(t, err)
			defer d.Close()

			for {
				var b = make([]byte, 1536)
				n, _, err := d.Recv(b)
				require.NoError(t, err)

				iphdr := header.IPv4(b[:n])
				tcphdr := header.TCP(iphdr.Payload())

				// fmt.Println(tcphdr.SourcePort(), "-->", tcphdr.DestinationPort())
				require.Equal(t, uint16(saddr.Port), tcphdr.SourcePort())
				require.Equal(t, uint16(caddr.Port), tcphdr.DestinationPort())
			}
		}()

		// client
		time.Sleep(time.Second * 3)
		conn, err := net.DialTCP("tcp", caddr, saddr)
		require.NoError(t, err)
		defer conn.Close()
	}

}

func Test_Divert_Auto_Handle_DF(t *testing.T) {
	src := &net.TCPAddr{IP: locIP, Port: int(randPort())}
	dst := &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: int(randPort())}

	go func() {
		time.Sleep(time.Second)

		b := buildRawTCP(t, src, dst, 1536) // size must > mtu
		addr := &divert.Address{Layer: divert.LAYER_NETWORK, Event: divert.NETWORK_PACKET}
		addr.SetOutbound(true)

		d, err := dll.Open("false", divert.LAYER_NETWORK, 1, divert.WRITE_ONLY)
		require.NoError(t, err)
		defer d.Close()
		_, err = d.Send(b, addr)
		require.NoError(t, err)
	}()

	filter := fmt.Sprintf(
		"!loopback and outbound and tcp and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
		src.IP, src.Port, dst.IP, dst.Port,
	)

	d, err := dll.Open(filter, divert.LAYER_NETWORK, 0, divert.READ_ONLY)
	require.NoError(t, err)
	defer d.Close()

	var b = make([]byte, 2048)
	n, _, err := d.Recv(b)
	require.NoError(t, err)
	require.Equal(t, 1536, n)
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
	time.Sleep(time.Second)

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
