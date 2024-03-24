package bpf

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_FilterDstPortAndSynFlag(t *testing.T) {
	var dstPort = 8080

	var ins = []bpf.Instruction{
		// load ip version
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},

		// ipv4
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 4, SkipTrue: 1},
		bpf.LoadMemShift{Off: 0},

		// ipv6
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 1},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 40},
	}

	ins = append(ins, []bpf.Instruction{
		// destination port
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// SYN flag
		bpf.LoadIndirect{Off: 13, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0b00000010},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0b00000010, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		bpf.RetConstant{Val: 0xffff},
	}...)

	vm, err := bpf.NewVM(ins)
	require.NoError(t, err)

	var b = []byte{
		0x45, 0x00, 0x00, 0x3c, 0x92, 0xe8, 0x00, 0x00,
		0x40, 0x06, 0x49, 0x9c, 0xac, 0x19, 0x20, 0x01,
		0xac, 0x19, 0x26, 0x04, 0x4e, 0x12, 0x1f, 0x90,
		0x3d, 0xce, 0x40, 0x70, 0x00, 0x00, 0x00, 0x00,
		0xa0, 0x02, 0x74, 0x80, 0x9a, 0x01, 0x00, 0x00,
		0x02, 0x04, 0x05, 0xd8, 0x01, 0x01, 0x08, 0x0a,
		0x97, 0x66, 0x1a, 0xdc, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07,
	}

	n, err := vm.Run(b)
	require.NoError(t, err)
	require.Equal(t, 0xffff, n)
}

func Test_iphdrLen(t *testing.T) {
	var ips = [][]byte{
		func() header.IPv4 {
			var b = make(header.IPv4, 64)
			b.Encode(&header.IPv4Fields{
				Protocol: uint8(header.TCPProtocolNumber),
				SrcAddr:  tcpip.AddrFrom4([4]byte{3: 1}),
				DstAddr:  tcpip.AddrFrom4([4]byte{1: 1}),
			})
			return b[:b.HeaderLength()]
		}(),
		func() header.IPv4 {
			var b = make(header.IPv4, 64)
			b.Encode(&header.IPv4Fields{
				Protocol: uint8(header.TCPProtocolNumber),
				SrcAddr:  tcpip.AddrFrom4([4]byte{0: 4}),
				DstAddr:  tcpip.AddrFrom4([4]byte{2: 1}),
				Options: header.IPv4OptionsSerializer{
					&header.IPv4SerializableRouterAlertOption{},
				},
			})
			return b[:b.HeaderLength()]
		}(),
		func() header.IPv6 {
			var b = make(header.IPv6, 64)
			b.Encode(&header.IPv6Fields{
				SrcAddr: tcpip.AddrFrom16([16]byte{11: 4}),
				DstAddr: tcpip.AddrFrom16([16]byte{2: 1}),
			})
			return b[:b.NextHeader()]
		}(),
	}

	var ins = iphdrLen()
	ins = append(ins,
		bpf.TXA{},
		bpf.RetA{},
	)

	for _, ip := range ips {
		v, err := bpf.NewVM(ins)
		require.NoError(t, err)
		n, err := v.Run(ip)
		require.NoError(t, err)
		require.Equal(t, len(ip), n)
	}

}

func Test_filterAddrs(t *testing.T) {
	var suits = []header.Network{
		func() header.IPv4 {
			var b = make(header.IPv4, 40)
			b.Encode(&header.IPv4Fields{
				Protocol: uint8(header.TCPProtocolNumber),
				SrcAddr:  tcpip.AddrFromSlice([]byte{1, 2, 3, 4}),
				DstAddr:  tcpip.AddrFromSlice([]byte{64, 255, 232, 1}),
			})
			return b
		}(),

		func() header.IPv6 {
			var b = make(header.IPv6, 40)
			b.Encode(&header.IPv6Fields{
				TrafficClass: uint8(header.TCPProtocolNumber),
				SrcAddr:      tcpip.AddrFrom16([16]byte{11: 1}),
				DstAddr:      tcpip.AddrFrom16([16]byte{7: 1}),
			})
			return b
		}(),
	}

	for _, e := range suits {
		var ins = filterAddrs(
			netip.MustParseAddr(e.SourceAddress().String()),
			netip.MustParseAddr(e.DestinationAddress().String()),
		)
		ins = append(ins,
			bpf.RetConstant{Val: 0xffff},
		)

		v, err := bpf.NewVM(ins)
		require.NoError(t, err)
		n, err := v.Run(func() []byte {
			if e, ok := e.(header.IPv4); ok {
				return e
			}
			return e.(header.IPv6)
		}())
		require.NoError(t, err)
		require.Equal(t, 0xffff, n)
	}

}

func Test_FilterAddress(t *testing.T) {
	var suits = []struct {
		name     string
		src, dst netip.AddrPort
		proto    tcpip.TransportProtocolNumber
		ret      int
		ip       []byte
	}{
		{
			name:  "hit-ipv4-tcp",
			src:   netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), 19986),
			dst:   netip.AddrPortFrom(netip.MustParseAddr("64.255.232.1"), 8080),
			proto: header.TCPProtocolNumber,
			ret:   0xffff,
			ip: func() []byte {
				var b = make(header.IPv4, 40)
				b.Encode(&header.IPv4Fields{
					Protocol: uint8(header.TCPProtocolNumber),
					SrcAddr:  tcpip.AddrFromSlice([]byte{1, 2, 3, 4}),
					DstAddr:  tcpip.AddrFromSlice([]byte{64, 255, 232, 1}),
				})
				header.TCP(b[20:]).Encode(
					&header.TCPFields{
						SrcPort: 19986,
						DstPort: 8080,
					},
				)
				return b
			}(),
		},
		{
			name:  "hit-ipv4_opt-tcp",
			src:   netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), 19986),
			dst:   netip.AddrPortFrom(netip.MustParseAddr("64.255.232.1"), 8080),
			proto: header.TCPProtocolNumber,
			ret:   0xffff,
			ip: func() []byte {
				var b = make(header.IPv4, 64)
				b.Encode(&header.IPv4Fields{
					Protocol: uint8(header.TCPProtocolNumber),
					SrcAddr:  tcpip.AddrFromSlice([]byte{1, 2, 3, 4}),
					DstAddr:  tcpip.AddrFromSlice([]byte{64, 255, 232, 1}),
					Options:  header.IPv4OptionsSerializer{&header.IPv4SerializableRouterAlertOption{}},
				})

				header.TCP(b[b.HeaderLength():]).Encode(
					&header.TCPFields{
						SrcPort: 19986,
						DstPort: 8080,
					},
				)
				return b
			}(),
		},
	}

	for _, e := range suits {
		ins := FilterEndpoint(e.proto, e.src, e.dst)
		vm, err := bpf.NewVM(ins)
		require.NoError(t, err)

		n, err := vm.Run(e.ip)
		require.NoError(t, err)
		require.Equal(t, e.ret, n)
	}

}
