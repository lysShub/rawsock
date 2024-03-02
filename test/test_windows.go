package test

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/lysShub/wintun-go"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// 两个互通的tun设备
type TunTuple struct {
	ap1, ap2     *wintun.Adapter
	Addr1, Addr2 netip.Addr
	statue       atomic.Uint32
}

func (t *TunTuple) start() error {
	go t.srv(t.ap1, t.ap2, t.Addr2)
	go t.srv(t.ap2, t.ap1, t.Addr1)
	return nil
}

func (t *TunTuple) srv(self, peer *wintun.Adapter, peerAddr netip.Addr) {
	for t.statue.Load() == 0 {
		p, err := self.ReceivePacket()
		if err != nil {
			panic(err)
		}

		switch header.IPVersion(p) {
		case 4:
			iphdr := header.IPv4(p)
			if netip.AddrFrom4(iphdr.DestinationAddress().As4()) == peerAddr {

				// if iphdr.TransportProtocol() == header.TCPProtocolNumber {
				// 	tcphdr := header.TCP(iphdr.Payload())

				// 	data := ""
				// 	if tcphdr.Flags().Contains(header.TCPFlagPsh) {
				// 		data = string(tcphdr.Payload())
				// 	}

				// 	fmt.Printf(
				// 		"%s:%d --> %s:%d  %s\n",
				// 		iphdr.SourceAddress(), tcphdr.SourcePort(), iphdr.DestinationAddress(), tcphdr.DestinationPort(),
				// 		data,
				// 	)
				// }

				np, err := peer.AllocateSendPacket(uint32(len(p)))
				if err != nil {
					panic(err)
				}
				copy(np, p)

				if err := peer.SendPacket(np); err != nil {
					panic(err)
				}
			}
		default:
		}
		self.ReleasePacket(p)
	}
	self.Close()
	t.statue.Add(1)
}

func (t *TunTuple) Close() error {
	t.statue.Store(1)
	for t.statue.Load() != 3 {
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

func CreateTunTuple() (*TunTuple, error) {
	wintun.MustLoad(wintun.DLL)

	var addrs = []netip.Addr{
		netip.AddrFrom4([4]byte{10, 0, 1, 123}),
		netip.AddrFrom4([4]byte{10, 0, 2, 123}),
	}
	var tt = &TunTuple{
		Addr1: addrs[0],
		Addr2: addrs[1],
	}

	for i, addr := range addrs {
		name := fmt.Sprintf("test%s", hex.EncodeToString([]byte(addr.String())))

		ap, err := wintun.CreateAdapter(name, wintun.TunType("Wintun"))
		if err != nil {
			return nil, err
		}

		luid, err := ap.GetAdapterLuid()
		if err != nil {
			return nil, err
		}
		err = luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(addr, 24)})
		if err != nil {
			return nil, err
		}

		if i == 0 {
			tt.ap1 = ap
		} else {
			tt.ap2 = ap
		}
	}
	return tt, tt.start()
}
