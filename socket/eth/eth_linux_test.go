//go:build linux
// +build linux

package eth

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/lysShub/sockit/device/tun"
	"github.com/lysShub/sockit/route"
	"github.com/lysShub/sockit/test"
	"github.com/mdlayher/arp"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Read(t *testing.T) {
	// curl baidu.com, and async read income tcp packet
	var (
		dst = test.Baidu()
	)

	t.Run("Read", func(t *testing.T) {
		conn, err := Listen("eth:ip4", "eth0")
		require.NoError(t, err)
		defer conn.Close()

		var retch = make(chan struct{})
		go func() {
			time.Sleep(time.Second)
			req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:80", dst.String()), nil)
			require.NoError(t, err)
			req.Host = "baidu.com"

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			close(retch)
		}()

		var eth = make(header.Ethernet, 1536)
		for ok := false; !ok; {
			n, err := conn.Read(eth)
			require.NoError(t, err)
			require.Equal(t, conn.LocalAddr().String(), eth.DestinationAddress().String())
			ip := eth[header.EthernetMinimumSize:n]

			if header.IPVersion(ip) == 4 {
				ip := header.IPv4(ip[:n])
				ok = ip.SourceAddress().String() == dst.String()
			}
		}
		<-retch
	})

	t.Run("ReadFrom", func(t *testing.T) {
		conn, err := Listen("eth:ip4", "eth0")
		require.NoError(t, err)
		defer conn.Close()

		var retch = make(chan struct{})
		go func() {
			time.Sleep(time.Second)
			req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:80", dst.String()), nil)
			require.NoError(t, err)
			req.Host = "baidu.com"

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			close(retch)
		}()

		var ip = make([]byte, 1536)
		for ok := false; !ok; {
			n, _, err := conn.Recvfrom(ip, 0)
			require.NoError(t, err)

			if header.IPVersion(ip) == 4 {
				ip := header.IPv4(ip[:n])
				ok = ip.SourceAddress().String() == dst.String()
			}
		}
		<-retch
	})
}

func Test_Write(t *testing.T) {
	// write icmp EchoReq to baidu.com, and read EchoReply
	var (
		dst     = test.Baidu()
		gateway = func() net.HardwareAddr {
			ifi, err := net.InterfaceByName("eth0")
			require.NoError(t, err)
			c, err := arp.Dial(ifi)
			require.NoError(t, err)
			rows, err := route.GetTable()
			require.NoError(t, err)
			hw, err := c.Resolve(rows[0].Next) // eth0 gateway
			require.NoError(t, err)
			return hw
		}()
	)

	t.Run("Write", func(t *testing.T) {
		conn, err := Listen("eth:ip4", "eth0")
		require.NoError(t, err)
		defer conn.Close()
		msg := "0123"
		eth := func(msg string) header.Ethernet {
			iphdr := test.BuildICMP(t, test.LocIP(), dst, header.ICMPv4Echo, []byte(msg))
			var p = make(header.Ethernet, len(iphdr)+header.EthernetMinimumSize)
			n := copy(p[header.EthernetMinimumSize:], iphdr)
			require.Equal(t, len(iphdr), n)
			p.Encode(&header.EthernetFields{
				SrcAddr: tcpip.LinkAddress(conn.LocalAddr().String()),
				DstAddr: tcpip.LinkAddress(gateway),
				Type:    header.IPv4ProtocolNumber,
			})
			return p
		}(msg)

		n, err := conn.Write(eth)
		require.NoError(t, err)
		require.Equal(t, len(eth), n)

		ipconn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: test.LocIP().AsSlice()})
		require.NoError(t, err)
		var b = make(header.ICMPv4, 1536)
		for {
			n, addr, err := ipconn.ReadFromIP(b)
			require.NoError(t, err)
			if addr.IP.Equal(dst.AsSlice()) && n > 8 && string(b[8:n]) == msg {
				break
			}
		}
	})

	t.Run("WriteTo", func(t *testing.T) {
		conn, err := Listen("eth:ip4", "eth0")
		require.NoError(t, err)
		defer conn.Close()
		msg := "abcd"

		ip := test.BuildICMP(t, test.LocIP(), dst, header.ICMPv4Echo, []byte(msg))
		err = conn.Sendto(ip, 0, gateway)
		require.NoError(t, err)

		ipconn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: test.LocIP().AsSlice()})
		require.NoError(t, err)
		var b = make(header.ICMPv4, 1536)
		for {
			n, addr, err := ipconn.ReadFromIP(b)
			require.NoError(t, err)
			if addr.IP.Equal(dst.AsSlice()) && n > 8 && string(b[8:n]) == msg {
				break
			}
		}
	})
}

func Test_ReadWrite_Loopback(t *testing.T) {
	// write eth to loopbak, and read it next

	t.Run("lo", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 19986)
			saddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 8080)
			eth   = func() header.Ethernet {
				ip := test.BuildRawTCP(t, caddr, saddr, []byte("hello"))
				test.ValidIP(t, ip)
				var pack = make(header.Ethernet, 14+len(ip))
				pack.Encode(&header.EthernetFields{
					SrcAddr: tcpip.LinkAddress(make([]byte, 6)),
					DstAddr: tcpip.LinkAddress(make([]byte, 6)),
					Type:    header.IPv4ProtocolNumber,
				})
				n := copy(pack[14:], ip)
				require.Equal(t, len(ip), n)
				return pack
			}()
		)
		conn, err := Listen("eth:ip4", "lo")
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write(eth)
		require.NoError(t, err)
		var ip = make(header.IPv4, 1536)
		for {
			n, _, err := conn.Recvfrom(ip[:cap(ip)], 0)
			require.NoError(t, err)
			ip = ip[:n]

			if ip.Protocol() == uint8(header.TCPProtocolNumber) {
				tcp := header.TCP(ip[ip.HeaderLength():])
				if tcp.SourcePort() == caddr.Port() && tcp.DestinationPort() == saddr.Port() {
					return
				} else {
					_, err = conn.Write(eth)
					require.NoError(t, err)
				}
			}
		}
	})

	t.Run("eth0", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP(), 19986)
			saddr = netip.AddrPortFrom(test.LocIP(), 8080)
			eth   = func() header.Ethernet {
				ip := test.BuildRawTCP(t, caddr, saddr, []byte("hello"))
				test.ValidIP(t, ip)
				var pack = make(header.Ethernet, 14+len(ip))

				i, err := net.InterfaceByName("eth0")
				require.NoError(t, err)
				pack.Encode(&header.EthernetFields{
					SrcAddr: tcpip.LinkAddress(i.HardwareAddr),
					DstAddr: tcpip.LinkAddress(i.HardwareAddr),
					Type:    header.IPv4ProtocolNumber,
				})
				n := copy(pack[14:], ip)
				require.Equal(t, len(ip), n)
				return pack
			}()
		)
		conn, err := Listen("eth:ip4", "lo")
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write(eth)
		require.NoError(t, err)
		var ip = make(header.IPv4, 1536)
		for {
			n, _, err := conn.Recvfrom(ip[:cap(ip)], 0)
			require.NoError(t, err)
			ip = ip[:n]

			if ip.Protocol() == uint8(header.TCPProtocolNumber) {
				tcp := header.TCP(ip[ip.HeaderLength():])

				if tcp.SourcePort() == caddr.Port() && tcp.DestinationPort() == saddr.Port() {
					return
				} else {
					_, err = conn.Write(eth)
					require.NoError(t, err)
				}
			}
		}
	})
}

func Test_Deadline(t *testing.T) {
	// test read deadline
	name := "tap1"
	tt, err := tun.Tap(name)
	require.NoError(t, err)
	defer tt.Close()
	err = tt.SetAddr(netip.MustParsePrefix("10.0.1.3/24"))
	require.NoError(t, err)

	ifi, err := net.InterfaceByName(name)
	require.NoError(t, err)
	conn, err := Listen("eth:ip4", ifi.Index)
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

func Test_Tun_Device(t *testing.T) {
	// test eth conn can't work on tun/tap device
	t.Skip("todo")
	// if debug.Debug() {
	// 	link := fmt.Sprintf("/sys/class/net/%s", ifi.Name)
	// 	path, err := filepath.EvalSymlinks(link)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	has := strings.HasPrefix(path, "/sys/devices/virtual")
	// 	if has {
	// 		return nil, errors.New("not support tun/tap device")
	// 	}
	// }

	t.Run("tap", func(t *testing.T) {
		ap, err := tun.Tap("tap1")
		require.NoError(t, err)
		// ip route change default via 10.0.3.1 dev test1
		err = ap.SetAddr(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 3, 7}), 24))
		require.NoError(t, err)

		hw := make([]byte, 6)
		rand.New(rand.NewSource(time.Now().UnixNano())).Read(hw)
		hw[0] = 0
		err = ap.SetHardware(hw)
		require.NoError(t, err)

		_, err = Listen("eth:ip4", ap.Name())
		require.Error(t, err)

		// require.NoError(t, err)
		// defer conn.Close()
		// var b = make([]byte, 1536)
		// for {
		// 	n, addr, err := conn.Recvfrom(b, 0)
		// 	require.NoError(t, err)
		// 	fmt.Println(n, addr)
		// }
	})

	t.Run("tun", func(t *testing.T) {
		ap, err := tun.Tun("tun1")
		require.NoError(t, err)
		// ip route change default via 10.0.3.1 dev test1
		err = ap.SetAddr(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 3, 7}), 24))
		require.NoError(t, err)

		_, err = Listen("eth:ip4", ap.Name())
		require.Error(t, err)

		// require.NoError(t, err)
		// defer conn.Close()
		// var b = make([]byte, 1536)
		// for {
		// 	n, addr, err := conn.Recvfrom(b, 0)
		// 	require.NoError(t, err)
		// 	fmt.Println(n, addr)
		// }
	})

	t.Run("test111", func(t *testing.T) {
		ap, err := tun.Tun("tun1")
		require.NoError(t, err)
		defer ap.Close()

		// tcpdump -i tun1 -w a.pcap
		//  icmp packet transmit on lo

		addr := netip.AddrFrom4([4]byte{10, 0, 3, 7})
		err = ap.SetAddr(netip.PrefixFrom(addr, 24))
		require.NoError(t, err)

		conn, err := Listen("eth:ip4", ap.Name())
		require.NoError(t, err)
		defer conn.Close()

		go func() {
			ip := test.BuildICMP(t, addr, test.LocIP(), header.ICMPv4Echo, []byte("msg1"))

			dst := net.HardwareAddr([]byte{0x00, 0x15, 0x5d, 0x96, 0x3f, 0x2f})

			for {

				err = conn.Sendto(ip, 0, dst)
				require.NoError(t, err)

				time.Sleep(time.Second)
			}

		}()

		var b = make([]byte, 1536)
		for {
			n, addr, err := conn.Recvfrom(b, 0)
			require.NoError(t, err)
			fmt.Println(n, addr)
		}
	})
}
