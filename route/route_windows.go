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

// GetTable get ipv4 route entries
func GetTable() (table Table, err error) {

	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, e := range rows {
		// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
		next := e.NextHop.Addr()
		if next.IsUnspecified() {
			next = netip.Addr{}
		}
		table = append(table, Entry{
			Dest:      e.DestinationPrefix.Prefix(),
			Next:      next,
			Interface: int32(e.InterfaceIndex),
			Metric:    int32(e.Metric),
		})
	}

	var ipmap = map[uint32]netip.Addr{}
	{
		var size uint32
		err := helper.GetIpAddrTable(nil, &size, false)
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, err
		}

		var b = make([]byte, size)
		err = helper.GetIpAddrTable(b, &size, true)
		if err != nil {
			return nil, err
		}
		ipaddrs := helper.MibIpAddrTable(b).MibIpAddrRows()
		for _, e := range ipaddrs {
			ipmap[e.Index] = e.Addr().Addr()
		}
	}

	for i, e := range table {
		a, has := ipmap[uint32(e.Interface)]
		if has {
			table[i].Addr = a
		}
	}
	return table, nil
}
