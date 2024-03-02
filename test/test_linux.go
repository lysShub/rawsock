package test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type TunTuple struct {
	ap1, ap2     *os.File
	Addr1, Addr2 netip.Addr
}

func (t *TunTuple) Close() error {
	return errors.Join(t.ap1.Close(), t.ap2.Close())
}

func CreateTunTuple(t require.TestingT) *TunTuple {
	var addrs = []netip.Addr{
		netip.AddrFrom4([4]byte{10, 0, 1, 123}),
		netip.AddrFrom4([4]byte{10, 0, 2, 123}),
	}

	var tt = &TunTuple{
		Addr1: addrs[0],
		Addr2: addrs[1],
	}

	for i, addr := range addrs {
		name := fmt.Sprintf("test%d", i+1)

		{
			file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
			require.NoError(t, err)
			if i == 0 {
				tt.ap1 = file
			} else {
				tt.ap2 = file
			}

			ifq, err := unix.NewIfreq(name)
			require.NoError(t, err)
			ifq.SetUint32(unix.IFF_TUN | unix.IFF_NO_PI)

			err = ioctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifq)
			require.NoError(t, err)
		}

		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		require.NoError(t, err)
		defer unix.Close(fd)

		{ // set flags
			ifq, err := unix.NewIfreq(name)
			require.NoError(t, err)

			ifq.SetUint32(ifq.Uint32() | unix.IFF_UP | unix.IFF_RUNNING)
			err = ioctlIfreq(fd, unix.SIOCSIFFLAGS, ifq)
			require.NoError(t, err)
		}

		{ // set ip
			ifq, err := unix.NewIfreq(name)
			require.NoError(t, err)
			err = ifq.SetInet4Addr(addr.AsSlice())
			require.NoError(t, err)

			err = ioctlIfreq(fd, unix.SIOCSIFADDR, ifq)
			require.NoError(t, err)
		}

		{ // set mask
			ifq, err := unix.NewIfreq(name)
			require.NoError(t, err)
			err = ifq.SetInet4Addr([]byte{0xff, 0xff, 0xff, 0})
			require.NoError(t, err)

			err = ioctlIfreq(fd, unix.SIOCSIFNETMASK, ifq)
			require.NoError(t, err)
		}
	}

	return tt
}

func ioctlIfreq(fd int, req uint, value *unix.Ifreq) (err error) {
	for i := 0; i < 5; i++ {
		err = unix.IoctlIfreq(fd, req, value)
		if errors.Is(err, unix.EBUSY) {
			time.Sleep(time.Second)
		} else {
			break
		}
	}
	return err
}
