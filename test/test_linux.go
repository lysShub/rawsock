package test

import (
	"fmt"
	"net/netip"

	"github.com/lysShub/rsocket/device/tun"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type TunTuple struct {
	ap1, ap2     *tun.Tun
	Name1, Name2 string
	Addr1, Addr2 netip.Addr
}

func (t *TunTuple) Close() error {
	var err error
	if e := t.ap1.Close(); e != nil {
		err = e
	}
	if e := t.ap2.Close(); e != nil {
		err = e
	}
	return err
}

func CreateTunTuple(t require.TestingT) *TunTuple {
	var addrs = []netip.Addr{
		netip.AddrFrom4([4]byte{10, 0, 1, 123}),
		netip.AddrFrom4([4]byte{10, 0, 2, 123}),
	}

	var tt = &TunTuple{
		Addr1: addrs[0],
		Addr2: addrs[1],
	}

	for i, addr := range addrs {
		name := fmt.Sprintf("test%d", i+1)

		ap, err := tun.CreateTun(name)
		require.NoError(t, err)

		require.NoError(t, ap.DelFlags(unix.IFF_NOARP))

		err = ap.SetAddr(netip.PrefixFrom(addr, 24))
		require.NoError(t, err)

		// var hw = make(net.HardwareAddr, 6)
		// _, err = rand.New(rand.NewSource(0)).Read(hw)
		// require.NoError(t, err)
		// hw[0] = 0
		// err = ap.SetHardware(hw)
		// require.NoError(t, err)

		if i == 0 {
			tt.ap1 = ap
			tt.Name1 = name
		} else {
			tt.ap2 = ap
			tt.Name2 = name
		}
	}
	return tt
}
