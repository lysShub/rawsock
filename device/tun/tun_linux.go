//go:build linux
// +build linux

package tun

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Tun struct {
	fd   *os.File
	name string
	addr netip.Prefix
}

func CreateTun(name string) (*Tun, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tun := &Tun{fd: file}
	if err = tun.init(name); err != nil {
		tun.Close()
		return nil, errors.WithStack(err)
	}
	return tun, nil
}

func (t *Tun) init(name string) error {
	// set nic name
	if ifq, err := unix.NewIfreq(name); err != nil {
		return errors.WithStack(err)
	} else {
		ifq.SetUint32(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(int(t.fd.Fd()), unix.TUNSETIFF, ifq)
		if err != nil {
			return errors.WithStack(err)
		}

		t.name = name
	}

	// start nic
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err != nil {
		return errors.WithStack(err)
	} else {
		defer unix.Close(fd)

		return t.AddFlags(unix.IFF_UP | unix.IFF_RUNNING)
	}
}

func (t *Tun) Close() error {
	return t.fd.Close()
}

func (t *Tun) Flags() (uint32, error) {
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err != nil {
		return 0, errors.WithStack(err)
	} else {
		defer unix.Close(fd)
		return t.flags(fd)
	}
}

func (t *Tun) flags(fd int) (uint32, error) {
	ifq, err := unix.NewIfreq(t.name)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifq)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return ifq.Uint32(), nil
}

func (t *Tun) AddFlags(flags uint32) error {
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err != nil {
		return errors.WithStack(err)
	} else {
		defer unix.Close(fd)
		return t.addFlags(fd, flags)
	}
}
func (t *Tun) addFlags(fd int, flags uint32) error {
	old, err := t.flags(fd)
	if err != nil {
		return err
	}
	return t.setFlags(fd, old|flags)
}

func (t *Tun) DelFlags(flags uint32) error {
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err != nil {
		return errors.WithStack(err)
	} else {
		defer unix.Close(fd)
		return t.delFlags(fd, flags)
	}
}

func (t *Tun) delFlags(fd int, flags uint32) error {
	old, err := t.flags(fd)
	if err != nil {
		return err
	}
	return t.setFlags(fd, old^flags)
}

func (t *Tun) setFlags(fd int, flags uint32) error {
	ifq, err := unix.NewIfreq(t.name)
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

func (t *Tun) Down() error {
	return t.DelFlags(unix.IFF_UP | unix.IFF_RUNNING)
}

func (t *Tun) Up() error {
	return t.AddFlags(unix.IFF_UP | unix.IFF_RUNNING)
}

func (t *Tun) Name() string { return t.name }

func (t *Tun) SetAddr(addr netip.Prefix) error {
	if !addr.IsValid() {
		return errors.Errorf("invalid address %s", addr.String())
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer unix.Close(fd)

	// set ip
	if ifq, err := unix.NewIfreq(t.name); err != nil {
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
	if ifq, err := unix.NewIfreq(t.name); err != nil {
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

	// todo: tap support
	// set broadcast
	// if !addr.IsSingleIP() && addr.Addr().Is4() {
	// 	if ifq, err := unix.NewIfreq(t.name); err != nil {
	// 		return errors.WithStack(err)
	// 	} else {
	// 		var bc = addr.Addr().AsSlice()
	// 		ornot(bc, subnet)

	// 		err = ifq.SetInet4Addr(bc)
	// 		if err != nil {
	// 			return errors.WithStack(err)
	// 		}
	// 		err = unix.IoctlIfreq(fd, unix.SIOCSIFBRDADDR, ifq)
	// 		if err != nil {
	// 			return errors.WithStack(err)
	// 		}
	// 	}
	// }

	t.addr = addr
	return nil
}

func ornot(x, y []byte) {
	n := min(len(x), len(y))
	for i := 0; i < n; i++ {
		x[i] = x[i] | (^y[i])
	}
}

func (t *Tun) SetHardware(hw net.HardwareAddr) error {
	return errors.New("tap support")

	if len(hw) != 6 || hw[0] != 0 {
		// https://man7.org/linux/man-pages/man7/netdevice.7.html
		// why "sa_data the L2 hardware address starting from byte 0." ?
		return errors.Errorf("invalid hardware address %s", hw.String())
	}

	// var proto uint16 = uint16(header.IPv4ProtocolNumber)
	// if t.addr.Addr().Is6() {
	// 	proto = uint16(header.IPv6ProtocolNumber)
	// }
	// int(htons(unix.ETH_P_ALL))

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer unix.Close(fd)
	// must down nic before set hardware
	if err = t.delFlags(fd, unix.IFF_UP|unix.IFF_RUNNING|unix.IFF_NOARP|unix.IFF_POINTOPOINT); err != nil {
		return err
	}
	defer t.addFlags(fd, unix.IFF_UP|unix.IFF_RUNNING)

	req, err := unix.NewIfreq(t.name)
	if err != nil {
		return errors.WithStack(err)
	}

	// https://man7.org/linux/man-pages/man7/netdevice.7.html
	type ifreqHwaddr struct {
		ifname     [unix.IFNAMSIZ]byte
		ifr_hwaddr unix.RawSockaddr
	}
	addr := unix.RawSockaddr{
		Family: unix.ARPHRD_ETHER,
	}
	for i, e := range hw {
		addr.Data[i] = int8(e)
	}
	(*ifreqHwaddr)(unsafe.Pointer(req)).ifr_hwaddr = addr

	err = unix.IoctlIfreq(fd, unix.SIOCSIFHWADDR, req)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func htons(b uint16) uint16 {
	return binary.BigEndian.Uint16(
		binary.NativeEndian.AppendUint16(nil, b),
	)
}
