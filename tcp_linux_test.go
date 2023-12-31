package raw

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var locIP = func() net.IP {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("114.114.114.114"), Port: 53})
	return (c.LocalAddr().(*net.UDPAddr)).IP
}()

func TestXxx(t *testing.T) {
	// netstack.CreateNetTUN()
}

func TestZzzz(t *testing.T) {

	const PF_PACKET = 17

	fd, err := unix.Socket(PF_PACKET, unix.SOCK_RAW|unix.SOCK_DGRAM, unix.ETH_P_IP|unix.ETH_P_ARP|unix.ETH_P_ALL)
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := unix.Read(fd, b)
	require.NoError(t, err)

	t.Log(n)

}

func TestKkkk(t *testing.T) {

	l, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: locIP})
	require.NoError(t, err)
	defer l.Close()

	var b = make([]byte, 1532)
	n, err := l.Read(b) // ip 包
	t.Log(n, err)

	hdr := header.IPv4(b[:n])
	src, dst := hdr.SourceAddress(), hdr.DestinationAddress()
	hdr.SetDestinationAddressWithChecksumUpdate(src)
	hdr.SetSourceAddressWithChecksumUpdate(dst)

	n, err = l.Write(hdr)
	t.Log(n, err)

	if err != nil {
		e := err.Error()
		t.Log(e)
	}

}
