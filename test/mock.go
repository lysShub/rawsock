package test

import (
	"context"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/lysShub/relraw"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type MockRaw struct {
	options
	t require.TestingT

	proto         tcpip.TransportProtocolNumber
	local, remote netip.AddrPort
	ip            *relraw.IPStack

	out chan header.IPv4
	in  chan header.IPv4
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

	client = &MockRaw{
		options: defaultOptions,
		local:   clientAddr,
		remote:  serverAddr,
		proto:   proto,
		out:     a,
		in:      b,
	}
	var err error
	client.ip, err = relraw.NewIPStack(client.local.Addr(), client.remote.Addr(), proto)
	require.NoError(t, err)

	server = &MockRaw{
		options: defaultOptions,
		local:   serverAddr,
		remote:  clientAddr,
		out:     b,
		in:      a,
	}
	server.ip, err = relraw.NewIPStack(server.local.Addr(), server.remote.Addr(), proto)
	require.NoError(t, err)

	for _, opt := range opts {
		opt(&client.options)
		opt(&server.options)
	}
	return client, server
}

var _ relraw.RawConn = (*MockRaw)(nil)

func (r *MockRaw) Close() error {
	return nil
}
func (r *MockRaw) Read(ip []byte) (n int, err error) {
	b := <-r.in
	r.valid(b, true)

	n = copy(ip, b)
	if n < len(b) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}
func (r *MockRaw) ReadCtx(ctx context.Context, p *relraw.Packet) (err error) {
	var ip header.IPv4
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ip = <-r.in:
	}
	r.valid(ip, true)

	b := p.Data()
	b = b[:cap(b)]
	n := copy(b, ip)
	if n < len(ip) {
		return io.ErrShortBuffer
	}
	p.SetLen(n)

	return nil
}
func (r *MockRaw) Write(ip []byte) (n int, err error) {
	r.valid(ip, false)
	if r.loss() {
		return len(ip), nil
	}

	r.out <- ip
	return len(ip), nil
}
func (r *MockRaw) WriteCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ip.AttachOutbound(p)

	if r.loss() {
		return nil
	}
	r.valid(p.Data(), false)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.out <- p.Data():
	}
	return nil
}
func (r *MockRaw) Inject(ip []byte) (err error) {
	r.valid(ip, true)

	r.in <- ip
	return nil
}
func (r *MockRaw) InjectCtx(ctx context.Context, p *relraw.Packet) (err error) {
	r.ip.AttachInbound(p)
	r.valid(p.Data(), true)

	var tmp = make([]byte, p.Len())
	copy(tmp, p.Data())
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
func (r *MockRaw) LocalAddrAddrPort() netip.AddrPort  { return r.local }
func (r *MockRaw) RemoteAddrAddrPort() netip.AddrPort { return r.remote }

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

	require.True(r.t, ip.IsChecksumValid())

	psoSum := header.PseudoHeaderChecksum(
		ip.TransportProtocol(),
		ip.SourceAddress(), ip.DestinationAddress(),
		uint16(len(ip)-int(ip.HeaderLength())),
	)
	sum1 := checksum.Checksum(ip.Payload(), 0)

	var sum uint16
	var tp header.Transport
	switch ip.TransportProtocol() {
	case header.TCPProtocolNumber:
		tp = header.TCP(ip.Payload())
		sum = checksum.Combine(psoSum, sum1)
	case header.UDPProtocolNumber:
		tp = header.UDP(ip.Payload())
		sum = checksum.Combine(psoSum, sum1)
	case header.ICMPv4ProtocolNumber:
		tp = header.ICMPv4(ip.Payload())
		sum = sum1
	case header.ICMPv6ProtocolNumber:
		tp = header.ICMPv6(ip.Payload())
		sum = sum1
	default:
		panic("")
	}

	require.Equal(r.t, sum, tp.Checksum())
}

func (r *MockRaw) validAddr(ip header.IPv4, inbound bool) {
	if !r.options.validAddr {
		return
	}

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
	validAddr     bool
	validChecksum bool
	delay         time.Duration
	pl            float32
}

var defaultOptions = options{
	validAddr:     false,
	validChecksum: false,
	delay:         0,
	pl:            0,
}

type Option func(*options)

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