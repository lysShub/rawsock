package eth

import (
	"net"
	"syscall"
	"time"
)

type Eth interface {
	Read(ip []byte) (int, error)
	Write(eth []byte) (int, error)
	Close() error
	SyscallConn() syscall.RawConn
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
