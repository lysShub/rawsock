//go:build linux
// +build linux

package eth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/lysShub/rsocket/device/tun"
	"github.com/lysShub/rsocket/route"
	"github.com/lysShub/rsocket/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Read(t *testing.T) {
	ifi, err := net.InterfaceByName("eth0")
	require.NoError(t, err)
	conn, err := NewETHIdx("eth:ip4", ifi.Index)
	require.NoError(t, err)
	defer conn.Close()

	var rip net.IP
	ips, err := net.LookupIP("baidu.com")
	require.NoError(t, err)
	for _, e := range ips {
		if rip = e.To4(); rip != nil {
			break
		}
	}
	if rip == nil {
		t.FailNow()
	}

	var retch = make(chan struct{})
	go func() {
		time.Sleep(time.Second)
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:80", rip.String()), nil)
		require.NoError(t, err)
		req.Host = "baidu.com"

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		close(retch)
	}()

	var b = make([]byte, 1536)
	var ok bool
	for !ok {
		n, err := conn.Read(b)
		require.NoError(t, err)

		if header.IPVersion(b) == 4 {
			ip := header.IPv4(b[:n])

			ok = ip.SourceAddress().String() == rip.String()
		}
	}
	<-retch
}

func Test_Write1(t *testing.T) {
	t.Skip("not support tun device")

	tt := test.CreateTunTuple(t)
	pack := func() []byte {
		es, err := route.GetTable()
		require.NoError(t, err)

		clientEntry, err := es.MatchRoot(tt.Addr1)
		require.NoError(t, err)
		src, err := clientEntry.HardwareAddr()
		require.NoError(t, err)

		serverEntry, err := es.MatchRoot(tt.Addr2)
		require.NoError(t, err)
		dst, err := serverEntry.HardwareAddr()
		require.NoError(t, err)

		ip := test.BuildRawTCP(t,
			netip.AddrPortFrom(tt.Addr1, 19986),
			netip.AddrPortFrom(tt.Addr2, 8080), nil,
		)

		eth := make(header.Ethernet, len(ip)+14)
		copy(eth[14:], ip)
		eth.Encode(&header.EthernetFields{
			SrcAddr: tcpip.LinkAddress(src),
			DstAddr: tcpip.LinkAddress(dst),
			Type:    header.IPv4ProtocolNumber,
		})
		return eth
	}()

	// recver
	go func() {
		ec, err := NewETHName("eth:ip4", tt.Name2)
		require.NoError(t, err)

		var b = make([]byte, 1536)
		for {
			n, err := ec.Read(b)
			require.NoError(t, err)
			if header.IPVersion(b) == 4 {
				ip := header.IPv4(b[:n])
				if ip.TransportProtocol() == header.TCPProtocolNumber {
					tcp := header.TCP(ip.Payload())

					fmt.Println(tcp.SourcePort(), tcp.DestinationPort())
					break
				}
			}
			fmt.Println("read", n)
		}
	}()

	// sender
	ec, err := NewETHName("eth:ip4", tt.Name1)
	require.NoError(t, err)
	_, err = ec.Write(pack[14:]) // tun device, juse send ip
	require.NoError(t, err)
}

func Test_Write(t *testing.T) {
	// todo: add tap
}

func Test_Deadline(t *testing.T) {
	name := "testeth"
	tt, err := tun.CreateTun(name)
	require.NoError(t, err)
	defer tt.Close()
	err = tt.SetAddr(netip.MustParsePrefix("10.0.1.3/24"))
	require.NoError(t, err)

	ifi, err := net.InterfaceByName(name)
	require.NoError(t, err)
	conn, err := NewETHIdx("eth:ip4", ifi.Index)
	require.NoError(t, err)
	defer conn.Close()

	var b = make([]byte, 1536)
	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	require.NoError(t, err)

	s := time.Now()
	n, err := conn.Read(b)
	require.True(t, errors.Is(err, os.ErrDeadlineExceeded))
	require.Zero(t, n)
	require.Less(t, time.Second-time.Millisecond*100, time.Since(s))
	require.Greater(t, time.Second+time.Millisecond*100, time.Since(s))
}
