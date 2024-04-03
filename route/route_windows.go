//go:build windows
// +build windows

package route

import (
	"net/netip"

	"github.com/lysShub/rsocket/helper"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type Raw = winipcfg.MibIPforwardRow2

// GetTable get ipv4 route entries
func GetTable() (table Table, err error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var ifs = map[uint32]*winipcfg.MibIPInterfaceRow{}
	for _, e := range rows {
		next := e.NextHop.Addr()
		// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
		if next.IsUnspecified() {
			next = netip.Addr{}
		}

		i, has := ifs[e.InterfaceIndex]
		if !has {
			i = &winipcfg.MibIPInterfaceRow{
				Family:        windows.AF_INET,
				InterfaceLUID: e.InterfaceLUID,
			}
			if err := helper.GetIpInterfaceEntry(i); err != nil {
				return nil, err
			}
			ifs[e.InterfaceIndex] = i
		}
		e.Metric += i.Metric

		table = append(table, Entry{
			Dest:      e.DestinationPrefix.Prefix(),
			Next:      next,
			Interface: e.InterfaceIndex,
			Metric:    e.Metric,
			raw:       e,
		})
	}

	var addrMap = map[uint32]netip.Addr{}
	addrs, err := getIpAddrs()
	if err != nil {
		return nil, err
	}
	for _, e := range addrs {
		addrMap[e.Index] = e.Addr().Addr()
	}
	for i, e := range table {
		a, has := addrMap[uint32(e.Interface)]
		if has {
			table[i].Addr = a
		}
	}
	return table, nil
}

func getIpAddrs() ([]helper.MibIpAddrRow, error) {
	var size uint32 = 512
	var b = make([]byte, size)
	err := helper.GetIpAddrTable(b, &size, false)
	if err == nil {
		return helper.MibIpAddrTable(b).MibIpAddrRows(), nil
	} else if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, err
	}

	b = make([]byte, size)
	err = helper.GetIpAddrTable(b, &size, true)
	if err != nil {
		return nil, err
	}
	return helper.MibIpAddrTable(b).MibIpAddrRows(), nil
}
