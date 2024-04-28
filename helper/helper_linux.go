//go:build linux
// +build linux

package helper

import (
	"encoding/binary"
	"net"
	"net/netip"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func Htons(b uint16) uint16 {
	return binary.BigEndian.Uint16(
		binary.NativeEndian.AppendUint16(nil, b),
	)
}

func IoctlGifname(ifi int) (string, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer unix.Close(fd)

	req, _ := unix.NewIfreq("")
	req.SetUint32(uint32(ifi))

	err = unix.IoctlIfreq(fd, unix.SIOCGIFNAME, req)
	if err != nil {
		return "", errors.WithStack(err)
	}
	name := req.Name()
	return name, nil
}

func IoctlGifhwaddr(ifi string) (net.HardwareAddr, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer unix.Close(fd)

	req, err := unix.NewIfreq(ifi)
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

func IoctlSifaddr(ifi string, addr netip.Prefix) error {
	if !addr.IsValid() {
		return errors.Errorf("invalid address %s", addr.String())
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer unix.Close(fd)

	// set ip
	if ifq, err := unix.NewIfreq(ifi); err != nil {
		return errors.WithStack(err)
	} else {
		err = ifq.SetInet4Addr(addr.Addr().AsSlice())
		if err != nil {
			return errors.WithStack(err)
		}

		err = unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifq)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// set mask
	subnet := net.CIDRMask(addr.Bits(), addr.Addr().BitLen())
	if ifq, err := unix.NewIfreq(ifi); err != nil {
		return errors.WithStack(err)
	} else {
		err = ifq.SetInet4Addr(subnet)
		if err != nil {
			return errors.WithStack(err)
		}

		err = unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, ifq)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func IoctlGifaddr(ifi string) (netip.Prefix, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return netip.Prefix{}, errors.WithStack(err)
	}
	defer unix.Close(fd)

	var ip []byte
	if ifq, err := unix.NewIfreq(ifi); err != nil {
		return netip.Prefix{}, errors.WithStack(err)
	} else {
		err = unix.IoctlIfreq(fd, unix.SIOCGIFADDR, ifq)
		if err != nil {
			return netip.Prefix{}, errors.WithStack(err)
		}

		ip, err = ifq.Inet4Addr()
		if err != nil {
			return netip.Prefix{}, errors.WithStack(err)
		}
	}

	var mask []byte
	if ifq, err := unix.NewIfreq(ifi); err != nil {
		return netip.Prefix{}, errors.WithStack(err)
	} else {
		err = unix.IoctlIfreq(fd, unix.SIOCGIFNETMASK, ifq)
		if err != nil {
			return netip.Prefix{}, errors.WithStack(err)
		}
		mask, err = ifq.Inet4Addr()
		if err != nil {
			return netip.Prefix{}, errors.WithStack(err)
		}
	}

	ones, bits := net.IPMask(mask).Size()
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || bits != addr.BitLen() {
		return netip.Prefix{}, errors.Errorf(
			"invalid address %s or mask %s",
			net.IP(ip).String(), net.IPMask(mask).String(),
		)
	}
	return netip.PrefixFrom(addr, ones), nil
}

func IoctlGifflags(ifi string) (uint32, error) {
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err != nil {
		return 0, errors.WithStack(err)
	} else {
		defer unix.Close(fd)
		return ioctlGifflags(ifi, fd)
	}
}

func ioctlGifflags(ifi string, fd int) (uint32, error) {
	ifq, err := unix.NewIfreq(ifi)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifq)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return ifq.Uint32(), nil
}

func IoctlSifflags(ifi string, flags uint32) error {
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err != nil {
		return errors.WithStack(err)
	} else {
		defer unix.Close(fd)
		return ioctlSifflags(ifi, fd, flags)
	}
}

func ioctlSifflags(ifi string, fd int, flags uint32) error {
	ifq, err := unix.NewIfreq(ifi)
	if err != nil {
		return errors.WithStack(err)
	}
	ifq.SetUint32(flags)

	err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifq)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// IoctlAifflags add interface flags
func IoctlAifflags(ifi string, flags uint32) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer unix.Close(fd)

	old, err := ioctlGifflags(ifi, fd)
	if err != nil {
		return err
	}
	new := old | flags
	if new == old {
		return nil
	}
	return ioctlSifflags(ifi, fd, new)
}

// IoctlDifflags del interface flags
func IoctlDifflags(ifi string, flags uint32) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer unix.Close(fd)

	old, err := ioctlGifflags(ifi, fd)
	if err != nil {
		return err
	}
	new := old ^ flags
	if new == old {
		return nil
	}
	return ioctlSifflags(ifi, fd, new)
}

func IoctlTSO(ifi string, enable bool) error {
	return ioctlEthTool(ifi, &ethtool_value{cmd: unix.ETHTOOL_STSO, data: intbool(enable)})
}

func IoctlGSO(ifi string, enable bool) error {
	return ioctlEthTool(ifi, &ethtool_value{cmd: unix.ETHTOOL_SGSO, data: intbool(enable)})
}

func IoctlGRO(ifi string, enable bool) error {
	return ioctlEthTool(ifi, &ethtool_value{cmd: unix.ETHTOOL_SGRO, data: intbool(enable)})
}

func IoctlGROHW(ifi string, enable bool) error {
	panic("todo")
	// return ioctlEthTool(ifi, &ethtool_value{cmd: unix.ETHTOOL_SGRO, data: intbool(enable)})
}

const (
	ETH_FLAG_TXVLAN = (1 << 7)  /* TX VLAN offload enabled */
	ETH_FLAG_RXVLAN = (1 << 8)  /* RX VLAN offload enabled */
	ETH_FLAG_LRO    = (1 << 15) /* LRO is enabled */
	ETH_FLAG_NTUPLE = (1 << 27) /* N-tuple filters enabled */
	ETH_FLAG_RXHASH = (1 << 28)
)

func IoctlLRO(ifi string, enable bool) error {
	val := &ethtool_value{cmd: unix.ETHTOOL_GFLAGS}
	if err := ioctlEthTool(ifi, val); err != nil {
		return err
	}
	var v uint32
	if enable {
		v = val.data | ETH_FLAG_LRO
	} else {
		v = val.data ^ ETH_FLAG_LRO
	}
	if val.data == v {
		return nil
	}

	return ioctlEthTool(ifi, &ethtool_value{cmd: unix.ETHTOOL_SFLAGS, data: v})
}

type ethtool_value struct {
	cmd  uint32
	data uint32
}

func ioctlEthTool(ifi string, val *ethtool_value) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	req, err := unix.NewIfreq(ifi)
	if err != nil {
		return err
	}

	valptr := uintptr(unsafe.Pointer(val))
	*(*uintptr)(
		unsafe.Add(unsafe.Pointer(req), unix.IFNAMSIZ),
	) = valptr

	err = unix.IoctlIfreq(fd, unix.SIOCETHTOOL, req)
	return err
}

func intbool(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func LoopbackInterface() (ifi string, err error) {
	if flags, err := IoctlGifflags("lo"); err != nil {
		return "", err
	} else {
		if flags&unix.IFF_UP != 0 {
			return "lo", nil
		}
	}
	return "", errors.New("todo: for-range interfaces")
}
