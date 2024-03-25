//go:build linux
// +build linux

package route

import (
	"net/netip"
	"sort"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// GetTable get ipv4 route entries
func GetTable() (Table, error) {
	// todo: set socket timeout
	tab, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		return Table{}, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return Table{}, err
	}

	var es Table
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		switch m.Header.Type {
		case unix.RTM_NEWROUTE:
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return Table{}, errors.WithStack(err)
			}

			rt := (*unix.RtMsg)(unsafe.Pointer(unsafe.SliceData(m.Data)))
			e := collectEntry(attrs, rt.Dst_len)
			if e.Valid() {
				es = append(es, e)
			}
		case unix.NLMSG_DONE:
			i = len(msgs) // break
		case unix.NLMSG_NOOP:
			continue
		case unix.NLMSG_ERROR:
			rt := (*unix.NlMsgerr)(unsafe.Pointer(unsafe.SliceData(m.Data)))
			return Table{}, errors.WithStack(unix.Errno(-rt.Error))
		default:
			return Table{}, errors.Errorf("unexpect nlmsghdr type 0x%02x", m.Header.Type)
		}
	}

	sort.Sort(entriesSortImpl(es))

	return es, nil
}

func GetBestInterface(dst netip.Addr) (entry Entry, err error) {
	if !dst.IsValid() {
		return Entry{}, errors.Errorf("invalid address %s", dst.String())
	}

	var es Table
	if dst.Is4() {
		if es, err = GetTable(); err != nil {
			return Entry{}, err
		}
	} else {
		return Entry{}, errors.New("not support ipv6")
	}

	e, err := es.MatchRoot(dst)
	return e, err
}

func collectEntry(attrs []syscall.NetlinkRouteAttr, ones uint8) Entry {
	var e Entry
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.RTA_GATEWAY:
			e.Addr, _ = netip.AddrFromSlice(attr.Value)
			if e.Addr.Is4() {
				e.Dest = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			} else if e.Addr.Is6() {
				e.Dest = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			}
		case unix.RTA_DST:
			addr, ok := netip.AddrFromSlice(attr.Value)
			if ok {
				e.Dest = netip.PrefixFrom(addr, int(ones))
			}
		case unix.RTA_SRC, unix.RTA_PREFSRC:
			e.Addr, _ = netip.AddrFromSlice(attr.Value)
		case unix.RTA_OIF:
			e.Ifidx = *(*int32)(unsafe.Pointer(unsafe.SliceData(attr.Value)))
		case unix.RTA_METRICS:
			e.Metrics = *(*int32)(unsafe.Pointer(unsafe.SliceData(attr.Value)))
		}
	}
	return e
}
