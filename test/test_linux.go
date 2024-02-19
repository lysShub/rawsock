package test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

type TunTuple struct {
	ap1, ap2     *os.File
	Addr1, Addr2 netip.Addr
}

func (t *TunTuple) Close() error {
	return errors.Join(t.ap1.Close(), t.ap2.Close())
}

func CreateTunTuple() (*TunTuple, error) {
	var addrs = tunTupleAddrsGener()

	var tt = &TunTuple{
		Addr1: addrs[0],
		Addr2: addrs[1],
	}

	for i, addr := range addrs {
		name := fmt.Sprintf("test%d", addr.As4()[3])

		{
			file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
			if err != nil {
				return nil, err
			}
			if i == 0 {
				tt.ap1 = file
			} else {
				tt.ap2 = file
			}

			ifq, err := unix.NewIfreq(name)
			if err != nil {
				return nil, err
			}
			ifq.SetUint32(unix.IFF_TUN | unix.IFF_NO_PI)

			err = unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifq)
			if err != nil {
				return nil, err
			}
		}

		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			return nil, err
		}
		defer unix.Close(fd)

		{ // set flags
			ifq, err := unix.NewIfreq(name)
			if err != nil {
				return nil, err
			}

			ifq.SetUint32(ifq.Uint32() | unix.IFF_UP | unix.IFF_RUNNING)
			if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifq); err != nil {
				return nil, err
			}
		}

		{ // set ip
			ifq, err := unix.NewIfreq(name)
			if err != nil {
				return nil, err
			}
			if err = ifq.SetInet4Addr(addr.AsSlice()); err != nil {
				return nil, err
			}

			if err = unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifq); err != nil {
				return nil, err
			}
		}
	}

	return tt, nil
}
