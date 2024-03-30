package tun_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/rsocket/device/tun"
	"github.com/lysShub/rsocket/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Tun_Conn(t *testing.T) {
	t.Skip("can't test on wsl")

	addr := netip.MustParsePrefix("10.0.3.7/24")

	ap, err := tun.Tun("test1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(addr)
	require.NoError(t, err)

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
	fmt.Println(rip.String())

	conn, err := net.DialTCP("tcp",
		&net.TCPAddr{IP: addr.Addr().AsSlice(), Port: 19986},
		&net.TCPAddr{IP: rip, Port: 80},
	)
	require.NoError(t, err)
	defer conn.Close()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:80", rip.String()), nil)
	require.NoError(t, err)
	req.Host = "baidu.com"

	resp, err := (&http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		Timeout: time.Second * 5,
	}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func Test_Tap_Create(t *testing.T) {
	ap, err := tun.Tap("testcreate")
	require.NoError(t, err)
	defer ap.Close()

	{
		err = ap.SetAddr(netip.MustParsePrefix("10.0.3.7/24"))
		require.NoError(t, err)

		addr, err := ap.Addr()
		require.NoError(t, err)
		require.Equal(t, netip.MustParsePrefix("10.0.3.7/24"), addr)
	}

	{
		var hw = make(net.HardwareAddr, 6)
		_, err = rand.New(rand.NewSource(0)).Read(hw)
		require.NoError(t, err)
		hw[0] = 0
		err = ap.SetHardware(hw)
		require.NoError(t, err)

		new, err := ap.Hardware()
		require.NoError(t, err)
		require.Equal(t, hw.String(), new.String())
	}
}

func Test_Tap(t *testing.T) {
	addr := netip.PrefixFrom(test.LocIP().Next(), 32)

	ap, err := tun.Tap("tap1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(addr)
	require.NoError(t, err)

	var b = make([]byte, 1536)
	for {
		n, err := ap.Read(context.Background(), b)
		require.NoError(t, err)

		eth := header.Ethernet(b[:n])

		fmt.Println("read", eth.DestinationAddress(), eth.SourceAddress())
	}
}

func Test_Tap_Conn_Server(t *testing.T) {
	// addr := netip.MustParsePrefix("172.18.0.1/24")
	addr := netip.PrefixFrom(test.LocIP().Next(), 32)
	// addr := netip.PrefixFrom(
	// 	netip.AddrFrom4([4]byte{10, 0, 0, 1}), 24,
	// )

	ap, err := tun.Tap("tap1")
	// ap, err := tun.Tun("tun1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(addr)
	require.NoError(t, err)

	go func() {
		var b = make([]byte, 1536)
		for {
			n, err := ap.Read(context.Background(), b)
			require.NoError(t, err)

			eth := header.Ethernet(b[:n])

			// fmt.Println("read", eth.DestinationAddress(), eth.SourceAddress())
			// fmt.Println(eth, header.IPVersion(b))

			t := m[uint32(eth.Type())]

			var ip header.Network
			if t == "ETH_P_IPV6" {
				ip = header.IPv6(eth[14:])
				src := netip.AddrFrom16(ip.SourceAddress().As16())
				if src.Is4In6() {
					src = netip.AddrFrom4(src.As4())
				}
				dst := netip.AddrFrom16(ip.DestinationAddress().As16())
				if dst.Is4In6() {
					dst = netip.AddrFrom4(dst.As4())
				}

				fmt.Println(src.String(), dst.String())
			}
			var p tcpip.TransportProtocolNumber
			if ip != nil {
				p = ip.TransportProtocol()
			}

			fmt.Println(t, p)
		}
	}()

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

	conn, err := net.DialTCP("tcp",
		&net.TCPAddr{IP: addr.Addr().AsSlice(), Port: int(test.RandPort())},
		&net.TCPAddr{IP: rip, Port: 80},
	)
	require.NoError(t, err)
	defer conn.Close()
	fmt.Println(conn.LocalAddr().String())

	req, err := http.NewRequest("GET", "http://baidu.com", nil)
	require.NoError(t, err)
	req.Host = "baidu.com"

	resp, err := (&http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	time.Sleep(time.Second * 10)
}

func Test_Tap_Loopback(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 3, 1}), 19986)

		// caddr = netip.AddrPortFrom(test.LocIP().Next(), 19986)
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)
	)

	var ret = make(chan struct{})
	go func() {
		defer func() { close(ret) }()
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: saddr.Addr().AsSlice(), Port: int(saddr.Port())})
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.AcceptTCP()
		require.NoError(t, err)
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	time.Sleep(time.Second)

	ap, err := tun.Tap("tap1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(netip.PrefixFrom(caddr.Addr(), 32))
	require.NoError(t, err)

	conn, err := net.DialTCP("tcp",
		&net.TCPAddr{IP: caddr.Addr().AsSlice(), Port: 19986},
		&net.TCPAddr{IP: test.LocIP().AsSlice(), Port: 8080},
	)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	<-ret
}

var m = map[uint32]string{
	0x88f7: "ETH_P_1588",
	0x88a8: "ETH_P_8021AD",
	0x88e7: "ETH_P_8021AH",
	0x8100: "ETH_P_8021Q",
	0x8917: "ETH_P_80221",
	0x4:    "ETH_P_802_2",
	0x1:    "ETH_P_802_3",
	0x600:  "ETH_P_802_3_MIN",
	0x88b5: "ETH_P_802_EX1",
	0x80f3: "ETH_P_AARP",
	0xfbfb: "ETH_P_AF_IUCV",
	0x3:    "ETH_P_ALL",
	0x88a2: "ETH_P_AOE",
	0x1a:   "ETH_P_ARCNET",
	0x806:  "ETH_P_ARP",
	0x809b: "ETH_P_ATALK",
	0x8884: "ETH_P_ATMFATE",
	0x884c: "ETH_P_ATMMPOA",
	0x2:    "ETH_P_AX25",
	0x4305: "ETH_P_BATMAN",
	0x8ff:  "ETH_P_BPQ",
	0xf7:   "ETH_P_CAIF",
	0xc:    "ETH_P_CAN",
	0xd:    "ETH_P_CANFD",
	0xe:    "ETH_P_CANXL",
	0x8902: "ETH_P_CFM",
	0x16:   "ETH_P_CONTROL",
	0x6006: "ETH_P_CUST",
	0x6:    "ETH_P_DDCMP",
	0x6000: "ETH_P_DEC",
	0x6005: "ETH_P_DIAG",
	0x6001: "ETH_P_DNA_DL",
	0x6002: "ETH_P_DNA_RC",
	0x6003: "ETH_P_DNA_RT",
	0x1b:   "ETH_P_DSA",
	0xdadb: "ETH_P_DSA_8021Q",
	0xe001: "ETH_P_DSA_A5PSW",
	0x18:   "ETH_P_ECONET",
	0xdada: "ETH_P_EDSA",
	0x88be: "ETH_P_ERSPAN",
	0x22eb: "ETH_P_ERSPAN2",
	0x88a4: "ETH_P_ETHERCAT",
	0x8906: "ETH_P_FCOE",
	0x8914: "ETH_P_FIP",
	0x19:   "ETH_P_HDLC",
	0x892f: "ETH_P_HSR",
	0x8915: "ETH_P_IBOE",
	0xf6:   "ETH_P_IEEE802154",
	0xa00:  "ETH_P_IEEEPUP",
	0xa01:  "ETH_P_IEEEPUPAT",
	0xed3e: "ETH_P_IFE",
	0x800:  "ETH_P_IP",
	0x86dd: "ETH_P_IPV6",
	0x8137: "ETH_P_IPX",
	0x17:   "ETH_P_IRDA",
	0x6004: "ETH_P_LAT",
	0x886c: "ETH_P_LINK_CTL",
	0x88cc: "ETH_P_LLDP",
	0x9:    "ETH_P_LOCALTALK",
	0x60:   "ETH_P_LOOP",
	0x9000: "ETH_P_LOOPBACK",
	0x88e5: "ETH_P_MACSEC",
	0xf9:   "ETH_P_MAP",
	0xfa:   "ETH_P_MCTP",
	0x15:   "ETH_P_MOBITEX",
	0x8848: "ETH_P_MPLS_MC",
	0x8847: "ETH_P_MPLS_UC",
	0x88e3: "ETH_P_MRP",
	0x88f5: "ETH_P_MVRP",
	0x88f8: "ETH_P_NCSI",
	0x894f: "ETH_P_NSH",
	0x888e: "ETH_P_PAE",
	0x8808: "ETH_P_PAUSE",
	0xf5:   "ETH_P_PHONET",
	0x10:   "ETH_P_PPPTALK",
	0x8863: "ETH_P_PPP_DISC",
	0x8:    "ETH_P_PPP_MP",
	0x8864: "ETH_P_PPP_SES",
	0x88c7: "ETH_P_PREAUTH",
	0x8892: "ETH_P_PROFINET",
	0x88fb: "ETH_P_PRP",
	0x200:  "ETH_P_PUP",
	0x201:  "ETH_P_PUPAT",
	0x9100: "ETH_P_QINQ1",
	0x9200: "ETH_P_QINQ2",
	0x9300: "ETH_P_QINQ3",
	0x8035: "ETH_P_RARP",
	0x8899: "ETH_P_REALTEK",
	0x6007: "ETH_P_SCA",
	0x8809: "ETH_P_SLOW",
	0x5:    "ETH_P_SNAP",
	0x890d: "ETH_P_TDLS",
	0x6558: "ETH_P_TEB",
	0x88ca: "ETH_P_TIPC",
	0x1c:   "ETH_P_TRAILER",
	0x11:   "ETH_P_TR_802_2",
	0x22f0: "ETH_P_TSN",
	0x7:    "ETH_P_WAN_PPP",
	0x883e: "ETH_P_WCCP",
	0x805:  "ETH_P_X25",
	0xf8:   "ETH_P_XDSA",
}
