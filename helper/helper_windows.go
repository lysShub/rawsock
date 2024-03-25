//go:build windows
// +build windows

package helper

import "net"

func IoctlGifname(ifi int) (string, error) {
	panic("todo")
}

func IoctlGifhwaddr(ifi string) (net.HardwareAddr, error) {
	panic("todo")
}
