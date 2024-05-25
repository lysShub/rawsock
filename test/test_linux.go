package test

import (
	"fmt"
	"net/netip"

	"github.com/lysShub/netkit/tun"

	"github.com/stretchr/testify/require"
)

type NicTuple struct {
	Ap1, Ap2     *tun.TunTap
	Name1, Name2 string
	Addr1, Addr2 netip.Addr
}

func (t *NicTuple) Close() error {
	var err error
	if e := t.Ap1.Close(); e != nil {
		err = e
	}
	if e := t.Ap2.Close(); e != nil {
		err = e
	}
	return err
}

func CreateTunTuple(t require.TestingT) *NicTuple {
	var addrs = []netip.Addr{
		netip.AddrFrom4([4]byte{10, 0, 1, 123}),
		netip.AddrFrom4([4]byte{10, 0, 2, 123}),
	}

	var tt = &NicTuple{
		Addr1: addrs[0],
		Addr2: addrs[1],
	}

	for i, addr := range addrs {
		name := fmt.Sprintf("test%d", i+1)

		ap, err := tun.Tun(name)
		require.NoError(t, err)

		err = ap.SetAddr(netip.PrefixFrom(addr, 24))
		require.NoError(t, err)

		if i == 0 {
			tt.Ap1 = ap
			tt.Name1 = name
		} else {
			tt.Ap2 = ap
			tt.Name2 = name
		}
	}
	return tt
}
