package test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal/config"
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
	ip            *relraw.IPStack

	in       chan header.IPv4
	out      chan<- header.IPv4
	closed   bool
	closedMu sync.RWMutex
}

type Option func(*options)

func RawOpts(opts ...relraw.Option) Option {
	return func(o *options) {
		for _, opt := range opts {
			opt(&o.Config)
		}
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
	client.ip, err = relraw.NewIPStack(
		client.local.Addr(), client.remote.Addr(),
		proto,
		client.options.Config.IPStackCfg.Unmarshal(),
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
	server.ip, err = relraw.NewIPStack(
		server.local.Addr(), server.remote.Addr(),
		proto,
		server.options.Config.IPStackCfg.Unmarshal(),
	)
	require.NoError(t, err)

	for _, opt := range opts {
		opt(&client.options)
		opt(&server.options)
	}
	return client, server
}

var _ relraw.RawConn = (*MockRaw)(nil)

func (r *MockRaw) Close() error {
	r.closedMu.Lock()
	defer r.closedMu.Unlock()
	r.closed = true
	close(r.out)
	return nil
}

func (r *MockRaw) Read(ip []byte) (n int, err error) {
	b, ok := <-r.in
	if !ok {
		return 0, io.EOF
	}
	r.valid(b, true)

	n = copy(ip, b)
	if n < len(b) {
		return 0, io.ErrShortBuffer
	}

	r.ip.UpdateInbound(ip[:n])
	return n, nil
}
func (r *MockRaw) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	var ip header.IPv4
	ok := false
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ip, ok = <-r.in:
		if !ok {
			return io.EOF
		}
	}
	r.valid(ip, true)

	b := p.Data()
	b = b[:cap(b)]
	n := copy(b, ip)
	if n < len(ip) {
		return io.ErrShortBuffer
	}
	p.SetLen(n)

	p.SetHead(p.Head() + int(ip.HeaderLength()))
	return nil
}
func (r *MockRaw) Write(ip []byte) (n int, err error) {
	r.closedMu.RLock()
	defer r.closedMu.RUnlock()
	if r.closed {
		return 0, os.ErrClosed
	}

	r.valid(ip, false)
	if r.loss() {
		return len(ip), nil
	}

	tmp := make([]byte, len(ip))
	copy(tmp, ip)

	r.ip.UpdateOutbound(tmp)
	r.out <- tmp

	return len(ip), nil
}
func (r *MockRaw) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.closedMu.RLock()
	defer r.closedMu.RUnlock()
	if r.closed {
		return os.ErrClosed
	}

	r.ip.AttachOutbound(p)

	r.valid(p.Data(), false)
	if r.loss() {
		return nil
	}

	tmp := make([]byte, p.Len())
	copy(tmp, p.Data())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.out <- tmp:
	}
	return nil
}
func (r *MockRaw) Inject(ip []byte) (err error) {
	r.valid(ip, true)

	var tmp = make([]byte, len(ip))
	copy(tmp, ip)

	defer func() {
		if recover() != nil {
			err = os.ErrClosed
		}
	}()

	r.ip.UpdateInbound(tmp)
	r.in <- tmp
	return nil
}
func (r *MockRaw) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ip.AttachInbound(p)
	r.valid(p.Data(), true)

	var tmp = make([]byte, p.Len())
	copy(tmp, p.Data())

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
func (r *MockRaw) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: r.local.Addr().AsSlice(), Port: int(r.local.Port())}
}
func (r *MockRaw) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: r.remote.Addr().AsSlice(), Port: int(r.remote.Port())}
}
func (r *MockRaw) LocalAddrPort() netip.AddrPort  { return r.local }
func (r *MockRaw) RemoteAddrPort() netip.AddrPort { return r.remote }

func (r *MockRaw) loss() bool {
	if r.pl < 0.000001 {
		return false
	}
	return rand.Uint32() <= uint32(float32(math.MaxUint32)*r.pl)
}

func (r *MockRaw) valid(ip header.IPv4, inboud bool) {
	r.validAddr(ip, inboud)
	r.validChecksum(ip)
}

func (r *MockRaw) validChecksum(ip header.IPv4) {
	if !r.options.validChecksum {
		return
	}

	ValidIP(r.t, ip)
}

func (r *MockRaw) validAddr(ip header.IPv4, inbound bool) {
	if !r.options.validAddr {
		return
	}
	require.Equal(r.t, r.proto, ip.TransportProtocol())

	var tp header.Transport
	switch ip.TransportProtocol() {
	case header.TCPProtocolNumber:
		tp = header.TCP(ip.Payload())
	case header.UDPProtocolNumber:
		tp = header.UDP(ip.Payload())
	case header.ICMPv4ProtocolNumber:
		tp = header.ICMPv4(ip.Payload())
	case header.ICMPv6ProtocolNumber:
		tp = header.ICMPv6(ip.Payload())
	default:
		panic("")
	}

	src := netip.AddrPortFrom(
		netip.AddrFrom4(ip.SourceAddress().As4()),
		tp.SourcePort(),
	)
	dst := netip.AddrPortFrom(
		netip.AddrFrom4(ip.DestinationAddress().As4()),
		tp.DestinationPort(),
	)
	if inbound {
		require.Equal(r.t, r.remote, src)
		require.Equal(r.t, r.local, dst)
	} else {
		require.Equal(r.t, r.local, src)
		require.Equal(r.t, r.remote, dst)
	}
}

type options struct {
	config.Config

	validAddr     bool
	validChecksum bool
	delay         time.Duration
	pl            float32
}

var defaultOptions = options{
	Config: config.Default,

	validAddr:     false,
	validChecksum: false,
	delay:         0,
	pl:            0,
}

type mockTest struct{}

func T() *mockTest { return &mockTest{} }

var _ require.TestingT = (*mockTest)(nil)

func (m *mockTest) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	fmt.Println()

	os.Exit(1)
}

func (m *mockTest) FailNow() {
	fmt.Println("Fail")
	os.Exit(1)
}

type MockConn struct {
	t                require.TestingT
	locAddr, remAddr net.Addr

	in  <-chan []byte
	out chan []byte

	// deadline
	// todo: chan time.Time
	r, w, rw chan struct{}

	closed   bool
	closedMu sync.RWMutex
}

func NewMockConn(
	t require.TestingT,
	clientAddr, serverAddr net.Addr,
) (c, s *MockConn) {

	var a, b = make(chan []byte, 16), make(chan []byte, 16)

	c = &MockConn{
		t:       t,
		locAddr: clientAddr,
		remAddr: serverAddr,

		in:  a,
		out: b,

		r:  make(chan struct{}, 2),
		w:  make(chan struct{}, 2),
		rw: make(chan struct{}, 4),
	}

	s = &MockConn{
		t:       t,
		locAddr: serverAddr,
		remAddr: clientAddr,

		in:  b,
		out: a,

		r:  make(chan struct{}, 2),
		w:  make(chan struct{}, 2),
		rw: make(chan struct{}, 4),
	}

	return c, s
}

var _ net.Conn = (*MockConn)(nil)

func (m *MockConn) Read(b []byte) (n int, err error) {
	select {
	case tmp, ok := <-m.in:
		if !ok {
			return 0, io.EOF
		}
		n = copy(b, tmp)
		return
	case <-m.r:
		return 0, os.ErrDeadlineExceeded
	case <-m.rw:
		return 0, os.ErrDeadlineExceeded
	}
}
func (m *MockConn) Write(b []byte) (n int, err error) {
	m.closedMu.RLock()
	defer m.closedMu.RUnlock()
	if m.closed {
		return 0, os.ErrClosed
	}

	tmp := make([]byte, len(b))
	copy(tmp, b)
	select {
	case m.out <- tmp:
		return len(tmp), nil
	case <-m.w:
		return 0, os.ErrDeadlineExceeded
	case <-m.rw:
		return 0, os.ErrDeadlineExceeded
	}
}
func (m *MockConn) Close() error {
	m.closedMu.Lock()
	defer m.closedMu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.out)
	}
	return nil
}
func (m *MockConn) LocalAddr() net.Addr  { return m.locAddr }
func (m *MockConn) RemoteAddr() net.Addr { return m.remAddr }
func (m *MockConn) SetDeadline(t time.Time) error {
	if time.Now().Before(t) {
		return errors.New("before deadline")
	}

	dur := time.Until(t)
	time.AfterFunc(dur, func() {
		select {
		case m.rw <- struct{}{}:
		default:
		}
	})
	return nil
}
func (m *MockConn) SetReadDeadline(t time.Time) error {
	if time.Now().Before(t) {
		return errors.New("before deadline")
	}

	dur := time.Until(t)
	time.AfterFunc(dur, func() {
		select {
		case m.r <- struct{}{}:
		default:
		}
	})
	return nil
}
func (m *MockConn) SetWriteDeadline(t time.Time) error {
	if time.Now().Before(t) {
		return errors.New("before deadline")
	}

	dur := time.Until(t)
	time.AfterFunc(dur, func() {
		select {
		case m.w <- struct{}{}:
		default:
		}
	})
	return nil
}
