//go:build linux
// +build linux

package tun

import (
	"net/netip"
	"os"

	"github.com/lysShub/rsocket/helper"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Tun struct {
	fd   *os.File
	name string
	addr netip.Prefix
}

func Create(name string) (*Tun, error) {
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
	return t.AddFlags(unix.IFF_UP | unix.IFF_RUNNING)
}
func (t *Tun) Name() string { return t.name }
func (t *Tun) Close() error { return t.fd.Close() }

func (t *Tun) Flags() (uint32, error) {
	return helper.IoctlGifflags(t.name)
}

func (t *Tun) AddFlags(flags uint32) error {
	return helper.IoctlAifflags(t.name, flags)
}

func (t *Tun) DelFlags(flags uint32) error {
	return helper.IoctlDifflags(t.name, flags)
}

func (t *Tun) SetAddr(addr netip.Prefix) error {
	err := helper.IoctlSifaddr(t.name, addr)
	if err != nil {
		return err
	}

	t.addr = addr
	return nil
}
