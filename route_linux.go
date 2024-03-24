//go:build linux
// +build linux

package rsocket

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Entry struct {
	Dest    netip.Prefix
	Addr    netip.Addr
	Ifidx   int32
	Metrics int32
}

func (e *Entry) Valid() bool {
	return e != nil && e.Dest.IsValid() && e.Ifidx != 0 && e.Addr.IsValid()
}

func (e *Entry) String() string {
	if !e.Valid() {
		return ""
	}

	return fmt.Sprintf(
		"%s %s %d %d",
		e.Dest.String(), e.Addr.String(), e.Ifidx, e.Metrics,
	)
}

func (e *Entry) Name() (string, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer unix.Close(fd)

	req, _ := unix.NewIfreq("")
	req.SetUint32(uint32(e.Ifidx))

	err = unix.IoctlIfreq(fd, unix.SIOCGIFNAME, req)
	if err != nil {
		return "", errors.WithStack(err)
	}
	name := req.Name()
	return name, nil
}

func (e *Entry) HardwareAddr() (net.HardwareAddr, error) {
	name, err := e.Name()
	if err != nil {
		return nil, err
	}
	return HardwareAddr(name)
}

func HardwareAddr(ifiName string) (net.HardwareAddr, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer unix.Close(fd)

	req, err := unix.NewIfreq(ifiName)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = unix.IoctlIfreq(fd, unix.SIOCGIFHWADDR, req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// https://man7.org/linux/man-pages/man7/netdevice.7.html
	type ifreqHwaddr struct {
		ifname     [unix.IFNAMSIZ]byte
		ifr_hwaddr unix.RawSockaddr
	}

	hwaddr := (*ifreqHwaddr)(unsafe.Pointer(req))
	switch hwaddr.ifr_hwaddr.Family {
	case unix.ARPHRD_ETHER:
	case unix.ARPHRD_NONE:
	// without hardware, such as tun device
	default:
		return nil, errors.Errorf("unexpect hwaddr family 0x%02x", hwaddr.ifr_hwaddr.Family)
	}

	var addr net.HardwareAddr
	for _, e := range hwaddr.ifr_hwaddr.Data[:6] {
		addr = append(addr, byte(e))
	}
	return addr, nil
}

type Entries []Entry

// Match route longest prefix Match
func (es Entries) Match(dst netip.Addr) Entry {
	for _, e := range es {
		if e.Dest.Contains(dst) {
			return e
		}
	}
	return Entry{}
}

func (es Entries) MatchRoot(dst netip.Addr) (Entry, error) {
	var cnt int
	e := es.matchRoot(dst, &cnt)
	if !e.Valid() {
		if cnt > loopLimit {
			return Entry{}, errors.New("cycle route")
		}
		return Entry{}, errors.WithStack(unix.ENETUNREACH)
	}
	return e, nil
}

const loopLimit = 64

func (es Entries) matchRoot(dst netip.Addr, cnt *int) Entry {
	*cnt = *cnt + 1
	if *cnt > loopLimit {
		return Entry{}
	}

	e := es.Match(dst)
	if e.Dest.IsSingleIP() {
		return e
	}
	return es.matchRoot(e.Addr, cnt)
}

func GetBestInterface(dst netip.Addr) (entry Entry, err error) {
	if !dst.IsValid() {
		return Entry{}, errors.Errorf("invalid address %s", dst.String())
	}

	var es Entries
	if dst.Is4() {
		if es, err = Route(); err != nil {
			return Entry{}, err
		}
	} else {
		return Entry{}, errors.New("not support ipv6")
	}

	e, err := es.MatchRoot(dst)
	return e, err
}

// Route get ipv4 route entries
func Route() (Entries, error) {
	// todo: set socket timeout
	tab, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		return Entries{}, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return Entries{}, err
	}

	var es Entries
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		switch m.Header.Type {
		case unix.RTM_NEWROUTE:
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return Entries{}, errors.WithStack(err)
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
			return Entries{}, errors.WithStack(unix.Errno(-rt.Error))
		default:
			return Entries{}, errors.Errorf("unexpect nlmsghdr type 0x%02x", m.Header.Type)
		}
	}

	sort.Sort(entriesSortImpl(es))

	return es, nil
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

type entriesSortImpl Entries

func (es entriesSortImpl) Len() int { return len(es) }
func (es entriesSortImpl) Less(i, j int) bool {
	// require desc
	bi, bj := es[i].Dest.Bits(), es[j].Dest.Bits()

	if bi >= bj {
		if bi == bj {
			return es[i].Metrics <= es[j].Metrics
		}
		return true
	}
	return false
}
func (es entriesSortImpl) Swap(i, j int) { es[i], es[j] = es[j], es[i] }
