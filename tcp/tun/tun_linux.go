//go:build linux
// +build linux

package tun

import "net"

func NewRawWithTUN(laddr, raddr *net.TCPAddr) (net.Conn, error) {
	return nil, nil
}
