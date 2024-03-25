//go:build linux
// +build linux

package helper

import (
	"net"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

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
