package test

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/helper/ipstack"
	"github.com/lysShub/sockit/packet"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type MockRaw struct {
	options
	id            string
	t             require.TestingT
	proto         tcpip.TransportProtocolNumber
	local, remote netip.AddrPort
	ip            *ipstack.IPStack

	in       chan header.IPv4
	out      chan<- header.IPv4
	closed   bool
	closedMu sync.RWMutex
}

type options struct {
	*conn.Config

	validAddr     bool
	validChecksum bool
	delay         time.Duration
	pl            float32
}

var defaultOptions = options{
	Config: conn.Options(),

	validAddr:     false,
	validChecksum: false,
	delay:         0,
	pl:            0,
}

type Option func(*options)

func RawOpts(opts ...conn.Option) Option {
	return func(o *options) {
		o.Config = conn.Options(opts...)
	}
}

func ValidAddr(o *options) {
	o.validAddr = true
}

func ValidChecksum(o *options) {
	o.validChecksum = true
}

// todo:
// func Delay(delay time.Duration) Option {
// 	return func(o *options) {
// 		o.delay = delay
// 	}
// }

func PacketLoss(pl float32) Option {
	return func(o *options) {
		o.pl = pl
	}
}

func NewMockRaw(
	t require.TestingT,
	proto tcpip.TransportProtocolNumber,
	clientAddr, serverAddr netip.AddrPort,
	opts ...Option,
) (client, server *MockRaw) {
	require.True(t, clientAddr.Addr().Is4())

	var a = make(chan header.IPv4, 16)
	var b = make(chan header.IPv4, 16)
	var err error

	client = &MockRaw{
		options: defaultOptions,
		id:      "client",
		t:       t,
		local:   clientAddr,
		remote:  serverAddr,
		proto:   proto,
		out:     a,
		in:      b,
	}
	for _, opt := range opts {
		opt(&client.options)
	}
	client.ip, err = ipstack.New(
		client.local.Addr(), client.remote.Addr(),
		proto,
		client.options.Config.IPStack.Unmarshal(),
	)
	require.NoError(t, err)

	server = &MockRaw{
		options: defaultOptions,
		id:      "server",
		t:       t,
		local:   serverAddr,
		remote:  clientAddr,
		proto:   proto,
		out:     b,
		in:      a,
	}
	for _, opt := range opts {
		opt(&client.options)
	}
	server.ip, err = ipstack.New(
		server.local.Addr(), server.remote.Addr(),
		proto,
		server.options.Config.IPStack.Unmarshal(),
	)
	require.NoError(t, err)

	for _, opt := range opts {
		opt(&client.options)
		opt(&server.options)
	}
	return client, server
}

var _ conn.RawConn = (*MockRaw)(nil)

func (r *MockRaw) Close() error {
	r.closedMu.Lock()
	defer r.closedMu.Unlock()

	if !r.closed {
		r.closed = true
		close(r.out)
	}
	return nil
}

func (r *MockRaw) Read(ctx context.Context, p *packet.Packet) (err error) {
	var ip header.IPv4
	ok := false
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ip, ok = <-r.in:
		if !ok {
			return errors.WithStack(os.ErrClosed)
		}
	}

	p.SetData(0)
	if p.Tail() < len(ip) {

		fmt.Println(p.Head(), p.Tail(), len(ip))

		return errors.WithStack(io.ErrShortBuffer)
	}
	p.Append(ip).SetData(len(ip))

	switch header.IPVersion(ip) {
	case 4:
		iphdr := int(header.IPv4(ip).HeaderLength())
		p.SetHead(p.Head() + iphdr)
	case 6:
		p.SetHead(p.Head() + header.IPv6MinimumSize)
	default:
		panic("")
	}

	return nil
}

func (r *MockRaw) Write(ctx context.Context, p *packet.Packet) (err error) {
	r.closedMu.RLock()
	defer r.closedMu.RUnlock()

	return r.writeLocked(ctx, p)
}

func (r *MockRaw) writeLocked(ctx context.Context, p *packet.Packet) (err error) {
	if r.closed {
		return errors.WithStack(os.ErrClosed)
	}

	if r.loss() {
		return r.writeLocked(ctx, p)
	}

	r.ip.AttachOutbound(p)

	tmp := make([]byte, p.Data())
	copy(tmp, p.Bytes())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.out <- tmp:
	}
	return nil
}
func (r *MockRaw) Inject(ctx context.Context, p *packet.Packet) (err error) {
	// r.valid(p.Data(), true)

	var tmp = make([]byte, p.Data())
	copy(tmp, p.Bytes())

	defer func() {
		if recover() != nil {
			err = os.ErrClosed
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.in <- tmp:
		return nil
	}
}
func (r *MockRaw) LocalAddr() netip.AddrPort  { return r.local }
func (r *MockRaw) RemoteAddr() netip.AddrPort { return r.remote }

func (r *MockRaw) loss() bool {
	return rand.Uint32() <= uint32(float32(math.MaxUint32)*r.pl)
}

type MockListener struct {
	addr netip.AddrPort
	raws chan conn.RawConn

	closed atomic.Bool
}

var _ conn.Listener = (*MockListener)(nil)

func NewMockListener(t require.TestingT, raws ...conn.RawConn) *MockListener {
	var addr = raws[0].LocalAddr()
	for _, e := range raws {
		require.Equal(t, addr, e.LocalAddr())
	}

	var l = &MockListener{
		addr: addr,
		raws: make(chan conn.RawConn, len(raws)),
	}
	for _, e := range raws {
		l.raws <- e
	}
	return l
}

func (l *MockListener) Accept() (conn.RawConn, error) {
	raw, ok := <-l.raws
	if !ok || l.closed.Load() {
		return nil, os.ErrClosed
	}
	return raw, nil
}

func (l *MockListener) Addr() netip.AddrPort { return l.addr }
func (l *MockListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.raws)
	}
	return nil
}
