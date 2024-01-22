package tcp

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/go-divert/embed"
	"github.com/lysShub/relraw"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var dll, loadErr = divert.LoadDivert(embed.DLL, embed.Sys)

func init() {
	if loadErr != nil {
		panic(loadErr)
	}
}

func TestXxxx(t *testing.T) {

	lip := relraw.LocalAddr()
	t.Log(lip)
	t.Log(lip.IsValid())
	return

	f := "tcp and !loopback and localPort=8080 and localAddr=192.168.0.104"

	d, err := dll.Open(f, divert.LAYER_SOCKET, 0, divert.READ_ONLY)
	require.NoError(t, err)
	d.Close()

}

func Test_Listen_Accept(t *testing.T) {
	addr := netip.AddrPortFrom(relraw.LocalAddr(), 8080)

	l, err := ListenWithDivert(dll, addr)
	require.NoError(t, err)
	conn, err := l.Accept()
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)
	iphdr := header.IPv4(b[:n])
	tcphdr := header.TCP(iphdr.Payload())

	s := fmt.Sprintf("%s:%d --> %s:%d", iphdr.SourceAddress(), tcphdr.SourcePort(), iphdr.DestinationAddress(), tcphdr.DestinationPort())

	t.Log(s)
}
