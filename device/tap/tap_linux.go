//go:build linux
// +build linux

package tap

import (
	"net"
	"net/netip"
	"os"
	"unsafe"

	"github.com/lysShub/rsocket/helper"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Tap struct {
	fd   *os.File
	name string
	addr netip.Prefix
}

func Create(name string) (*Tap, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tun := &Tap{fd: file}
	if err = tun.init(name); err != nil {
		tun.Close()
		return nil, errors.WithStack(err)
	}
	return tun, nil
}

func (t *Tap) init(name string) error {
	// set nic name
	if ifq, err := unix.NewIfreq(name); err != nil {
		return errors.WithStack(err)
	} else {
		ifq.SetUint32(unix.IFF_TAP | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(int(t.fd.Fd()), unix.TUNSETIFF, ifq)
		if err != nil {
			return errors.WithStack(err)
		}

		t.name = name
	}

	// start nic
	return t.AddFlags(unix.IFF_UP | unix.IFF_RUNNING)
}

func (t *Tap) Close() error {
	return t.fd.Close()
}

func (t *Tap) Flags() (uint32, error) {
	return helper.IoctlGifflags(t.name)
}

func (t *Tap) AddFlags(flags uint32) error {
	return helper.IoctlAifflags(t.name, flags)
}

func (t *Tap) DelFlags(flags uint32) error {
	return helper.IoctlDifflags(t.name, flags)
}

func (t *Tap) Name() string { return t.name }

func (t *Tap) SetAddr(addr netip.Prefix) error {
	err := helper.IoctlSifaddr(t.name, addr)
	if err != nil {
		return err
	}

	t.addr = addr
	return nil
}

func (t *Tap) Addr() (netip.Prefix, error) {
	return helper.IoctlGifaddr(t.name)
}

func (t *Tap) SetHardware(hw net.HardwareAddr) error {
	if len(hw) != 6 || hw[0] != 0 {
		// https://man7.org/linux/man-pages/man7/netdevice.7.html
		// why "sa_data the L2 hardware address starting from byte 0." ?
		return errors.Errorf("invalid hardware address %s", hw.String())
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer unix.Close(fd)
	// must down nic before set hardware
	if err := t.DelFlags(unix.IFF_UP | unix.IFF_RUNNING); err != nil {
		return err
	}
	defer t.AddFlags(unix.IFF_UP | unix.IFF_RUNNING)

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

func (t *Tap) Hardware() (net.HardwareAddr, error) {
	return helper.IoctlGifhwaddr(t.name)
}
