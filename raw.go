package relraw

import (
	"net"
	"syscall"
	"time"
)

type Raw interface {
	Close() error

	// read ip packet
	Read(b []byte) (n int, err error)

	// write ip packet
	Write(b []byte) (n int, err error)

	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SyscallConn() (syscall.RawConn, error)
}
