//go:build windows
// +build windows

package tun

import "net"

// with wintun
func NewRawWithTUN(laddr, raddr *net.TCPAddr) (net.Conn, error) {

	return nil, nil
}