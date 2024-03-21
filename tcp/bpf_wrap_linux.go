package tcp

import (
	"io"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

type PacketConnWrap struct {
	*ipv4.PacketConn
	raw    syscall.RawConn
	remote *net.IPAddr
}

var _ iconn = (*PacketConnWrap)(nil)

func (p *PacketConnWrap) Read(b []byte) (int, error) {
	msgs := []ipv4.Message{{
		Buffers: [][]byte{b},
	}}

	n, err := p.PacketConn.ReadBatch(msgs, syscall.MSG_TRUNC)
	if err != nil {
		return 0, err
	}

	if n == 1 {
		return int(msgs[0].N), nil
	} else {
		return 0, io.EOF
	}
}

func (p *PacketConnWrap) Write(b []byte) (int, error) {

	n, err := p.PacketConn.WriteTo(b, &ipv4.ControlMessage{}, p.remote)
	return n, err
}

func (p *PacketConnWrap) RemoteAddr() net.Addr {
	return p.remote
}

func (p *PacketConnWrap) SyscallConn() (syscall.RawConn, error) {
	return p.raw, nil
}

type RawConnWrap struct {
	*ipv4.RawConn
	remote *net.IPAddr
}

func (p *RawConnWrap) Read(b []byte) (int, error) {

	msgs := []ipv4.Message{{
		Buffers: [][]byte{b},
	}}

	n, err := p.RawConn.ReadBatch(msgs, syscall.MSG_TRUNC)
	if err != nil {
		return 0, err
	}

	if n == 1 {
		return int(msgs[0].N), nil
	} else {
		return 0, io.EOF
	}
}

func (p *RawConnWrap) Write(b []byte) (int, error) {

	n, err := p.RawConn.WriteToIP(b, p.remote)
	return n, err
}
