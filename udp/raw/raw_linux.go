//go:build linux
// +build linux

package raw

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/helper"
	"github.com/lysShub/rawsock/helper/bind"
	"github.com/lysShub/rawsock/helper/bpf"
	"github.com/lysShub/rawsock/helper/ipstack"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
)

// todo: Listener maybe user-route

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (*Conn, error) {
	cfg := rawsock.Options(opts...)

	if l, err := helper.DefaultLocal(laddr.Addr(), raddr.Addr()); err != nil {
		return nil, errors.WithStack(err)
	} else {
		laddr = netip.AddrPortFrom(l, laddr.Port())
	}

	fd, laddr, err := bind.BindLocal(header.UDPProtocolNumber, laddr, cfg.UsedPort)
	if err != nil {
		return nil, err
	}

	var c = newConnect(laddr, raddr, cfg.CtxPeriod)
	c.udp = fd

	if err := c.init(cfg); err != nil {
		return nil, c.close(err)
	}
	return c, nil
}

type Conn struct {
	laddr, raddr netip.AddrPort
	ctxPeriod    time.Duration
	udp          int

	raw     *net.IPConn
	ipstack *ipstack.IPStack

	closeErr atomic.Pointer[error]
}

var _ rawsock.RawConn = (*Conn)(nil)

func (c *Conn) close(cause error) error {
	if c.closeErr.CompareAndSwap(nil, &net.ErrClosed) {
		if c.raw != nil {
			if err := c.raw.Close(); err != nil {
				cause = err
			}
		}

		if c.udp != 0 {
			if err := syscall.Close(c.udp); err != nil {
				cause = errors.WithStack(err)
			}
		}

		if cause != nil {
			c.closeErr.Store(&cause)
		}
		return cause
	}
	return *c.closeErr.Load()
}
func newConnect(laddr, raddr netip.AddrPort, ctxPeriod time.Duration) *Conn {
	return &Conn{laddr: laddr, raddr: raddr, ctxPeriod: ctxPeriod}
}
func (c *Conn) init(cfg *rawsock.Config) (err error) {
	if c.raw, err = net.DialIP(
		"ip:udp",
		&net.IPAddr{IP: c.laddr.Addr().AsSlice()},
		&net.IPAddr{IP: c.raddr.Addr().AsSlice()},
	); err != nil {
		return errors.WithStack(err)
	}

	if raw, err := c.raw.SyscallConn(); err != nil {
		return errors.WithStack(err)
	} else {
		err := bpf.SetRawBPF(raw,
			bpf.FilterPorts(c.raddr.Port(), c.laddr.Port()),
		)
		if err != nil {
			return err
		}
	}

	if c.ipstack, err = ipstack.New(
		c.laddr.Addr(), c.raddr.Addr(),
		header.TCPProtocolNumber,
		cfg.IPStack.Unmarshal(),
	); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Read(ctx context.Context, pkt *packet.Packet) (err error) {
	b := pkt.Bytes()

	var n int
	for {
		err = c.raw.SetReadDeadline(time.Now().Add(c.ctxPeriod))
		if err != nil {
			return err
		}

		n, err = c.raw.Read(b[:cap(b)])
		if err == nil {
			break
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		} else {
			return err
		}
	}
	pkt.SetData(n)

	hdrLen, err := helper.IntegrityCheck(pkt.Bytes())
	if err != nil {
		return err
	}
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	pkt.SetHead(pkt.Head() + int(hdrLen))
	return nil
}
func (c *Conn) Write(_ context.Context, pkt *packet.Packet) (err error) {
	_, err = c.raw.Write(pkt.Bytes())
	return err
}
func (c *Conn) Inject(_ context.Context, pkt *packet.Packet) (err error) {
	defer pkt.DetachN(c.ipstack.Size())
	c.ipstack.AttachInbound(pkt)
	if debug.Debug() {
		test.ValidIP(test.P(), pkt.Bytes())
	}
	_, err = c.raw.Write(pkt.Bytes())
	return err
}
func (c *Conn) LocalAddr() netip.AddrPort  { return c.laddr }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.raddr }
func (c *Conn) Close() error               { return c.close(nil) }
