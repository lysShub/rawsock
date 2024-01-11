package tcp

import (
	"net"
	"syscall"
	"time"
)

type RawTCP interface {
	Close() error

	// read ip packet
	Read(b []byte) (n int, err error)

	// write tcp packet
	Write(b []byte) (n int, err error)
	WriteTo(b []byte, ip *net.IPAddr) (n int, err error)

	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SyscallConn() (syscall.RawConn, error)
}
