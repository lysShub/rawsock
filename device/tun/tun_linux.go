//go:build linux
// +build linux

package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/lysShub/rsocket/helper"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const cloneTunPath = "/dev/net/tun"

type TunTap struct {
	fd   *os.File
	name string
	addr netip.Prefix
	tun  bool
}

func Tun(name string) (*TunTap, error) {
	return Create(name, unix.IFF_TUN|unix.IFF_NO_PI)
}

func Tap(name string) (*TunTap, error) {
	return Create(name, unix.IFF_TAP|unix.IFF_NO_PI)
}

// Create
//
// e.g:
// Create("tun0", unix.IFF_TUN)
// Create("tap0", unix.IFF_TAP|unix.IFF_TUN_EXCL)
func Create(name string, flags uint32) (*TunTap, error) {
	var tap = &TunTap{}
	if flags&unix.IFF_TUN != 0 && flags&unix.IFF_TAP == 0 {
		tap.tun = true
	} else if flags&unix.IFF_TUN == 0 && flags&unix.IFF_TAP != 0 {
		tap.tun = false
	} else {
		return nil, errors.New("invalid flags")
	}

	fd, err := unix.Open(cloneTunPath, unix.O_RDWR, 0) // |unix.O_CLOEXEC
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if ifq, err := unix.NewIfreq(name); err != nil {
		unix.Close(fd)
		return nil, errors.WithStack(err)
	} else {
		ifq.SetUint32(flags)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifq)
		if err != nil {
			unix.Close(fd)
			return nil, errors.WithStack(err)
		}
		tap.name = name
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	tap.fd = os.NewFile(uintptr(fd), cloneTunPath)

	if err := tap.AddFlags(unix.IFF_UP | unix.IFF_RUNNING); err != nil {
		tap.Close()
		return nil, err
	}
	return tap, nil
}

func (t *TunTap) Name() string { return t.name }
func (t *TunTap) Close() error { return t.fd.Close() }

func (t *TunTap) Flags() (uint32, error) {
	return helper.IoctlGifflags(t.name)
}

func (t *TunTap) AddFlags(flags uint32) error {
	return helper.IoctlAifflags(t.name, flags)
}

func (t *TunTap) DelFlags(flags uint32) error {
	return helper.IoctlDifflags(t.name, flags)
}

func (t *TunTap) Addr() (netip.Prefix, error) {
	return helper.IoctlGifaddr(t.name)
}

func (t *TunTap) SetAddr(addr netip.Prefix) error {
	err := helper.IoctlSifaddr(t.name, addr)
	if err != nil {
		return err
	}

	t.addr = addr
	return nil
}

func (t *TunTap) SetHardware(hw net.HardwareAddr) error {
	if t.tun {
		return errors.New("tun device not support")
	}

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

func (t *TunTap) Hardware() (net.HardwareAddr, error) {
	return helper.IoctlGifhwaddr(t.name)
}

const ctxPeriod = time.Millisecond * 100

func (t *TunTap) Read(ctx context.Context, eth []byte) (int, error) {
	for {
		err := t.fd.SetReadDeadline(time.Now().Add(ctxPeriod))
		if err != nil {
			return 0, errors.WithStack(err)
		}

		n, err := t.fd.Read(eth)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return 0, errors.WithStack(err)
		}
		return n, nil
	}
}

func (t *TunTap) Write(_ context.Context, eth []byte) (int, error) {
	n, err := t.fd.Write(eth)
	return n, err
}
