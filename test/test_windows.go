package test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/lysShub/wintun-go"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type NicTuple struct {
	ap1, ap2     *wintun.Adapter
	Addr1, Addr2 netip.Addr
	statue       atomic.Uint32
}

func (t *NicTuple) start() error {
	go t.srv(t.ap1, t.ap2, t.Addr2)
	go t.srv(t.ap2, t.ap1, t.Addr1)
	return nil
}

func (t *NicTuple) srv(self, peer *wintun.Adapter, peerAddr netip.Addr) {
	for t.statue.Load() == 0 {
		p, err := self.Recv(context.Background())
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

				np, err := peer.Alloc(len(p))
				if err != nil {
					panic(err)
				}
				copy(np, p)

				if err := peer.Send(np); err != nil {
					panic(err)
				}
			}
		default:
		}
		self.Release(p)
	}
	self.Close()
	t.statue.Add(1)
}

func (t *NicTuple) Close() error {
	t.statue.Store(1)
	for t.statue.Load() != 3 {
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

func CreateTunTuple() (*NicTuple, error) {
	wintun.MustLoad(wintun.DLL)

	var addrs = []netip.Addr{
		netip.AddrFrom4([4]byte{10, 0, 1, 123}),
		netip.AddrFrom4([4]byte{10, 0, 2, 123}),
	}
	var tt = &NicTuple{
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
			if err = luid.AddRoute(
				netip.PrefixFrom(addrs[1], 32),
				netip.AddrFrom4([4]byte{0, 0, 0, 0}),
				30,
			); err != nil {
				return nil, err
			}
		} else {
			tt.ap2 = ap
			if err = luid.AddRoute(
				netip.PrefixFrom(addrs[0], 32),
				netip.AddrFrom4([4]byte{0, 0, 0, 0}),
				5,
			); err != nil {
				return nil, err
			}
		}
	}
	return tt, tt.start()
}
