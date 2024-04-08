package test

import (
	"context"
	"io"
	"math"
	"math/rand"
	"net/netip"
	"os"
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

	in     chan pack
	out    chan<- pack
	closed chan struct{}
}

type pack struct {
	ip header.IPv4
	t  time.Time // write time
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

func Delay(delay time.Duration) Option {
	return func(o *options) {
		o.delay = delay
	}
}

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

	var a = make(chan pack, 64)
	var b = make(chan pack, 64)
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
		closed:  make(chan struct{}),
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
		closed:  make(chan struct{}),
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
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func (r *MockRaw) Read(ctx context.Context, pkt *packet.Packet) (err error) {
	var p pack
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.closed:
		select {
		case p = <-r.in:
		default:
			return errors.WithStack(os.ErrClosed)
		}
	case p = <-r.in:
	}
	if d := time.Since(p.t); d < r.delay {
		time.Sleep(r.delay - d)
	}

	pkt.SetData(0)
	if pkt.Tail() < len(p.ip) {
		return errors.WithStack(io.ErrShortBuffer)
	}
	pkt.Append(p.ip).SetData(len(p.ip))

	switch header.IPVersion(p.ip) {
	case 4:
		iphdr := int(header.IPv4(p.ip).HeaderLength())
		pkt.SetHead(pkt.Head() + iphdr)
	case 6:
		pkt.SetHead(pkt.Head() + header.IPv6MinimumSize)
	default:
		panic("")
	}

	return nil
}

func (r *MockRaw) Write(ctx context.Context, pkt *packet.Packet) (err error) {
	select {
	case <-r.closed:
		return errors.WithStack(os.ErrClosed)
	default:
	}
	if r.loss() {
		return nil
	}

	r.ip.AttachOutbound(pkt)
	tmp := append([]byte{}, pkt.Bytes()...)
	select {
	case <-r.closed:
		return errors.WithStack(os.ErrClosed)
	case <-ctx.Done():
		return ctx.Err()
	case r.out <- pack{ip: tmp, t: time.Now()}:
	}
	return nil
}

func (r *MockRaw) Inject(ctx context.Context, p *packet.Packet) (err error) {
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
	case r.in <- pack{ip: tmp, t: time.Unix(0, 0)}:
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
