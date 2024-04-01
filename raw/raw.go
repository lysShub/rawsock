package raw

import (
	"net"
	"syscall"
	"time"
)

type Raw interface {
	Read(pack []byte) (int, error)
	Write(ip []byte) (int, error)
	Close() error
	SyscallConn() syscall.RawConn
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
