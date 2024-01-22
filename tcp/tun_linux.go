//go:build linux
// +build linux

package tcp

import "net"

func NewRawWithTUN(laddr, raddr *net.TCPAddr) (net.Conn, error) {
	return nil, nil
}
