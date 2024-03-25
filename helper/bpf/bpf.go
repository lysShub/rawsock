package bpf

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/net/bpf"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// todo: general bpf

func FilterDstPortAndSynFlag(port uint16) []bpf.Instruction {
	var ins = iphdrLen()

	const syn = uint32(header.TCPFlagSyn)
	ins = append(ins, []bpf.Instruction{
		// destination port
		bpf.LoadIndirect{Off: header.TCPDstPortOffset, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// SYN flag
		bpf.LoadIndirect{Off: header.TCPFlagsOffset, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: syn},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syn, SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		bpf.RetConstant{Val: 0xffff},
	}...)

	return ins
}

func FilterPorts(srcPort, dstPort uint16) []bpf.Instruction {
	var ins = iphdrLen()

	ins = append(ins, filterPorts(srcPort, dstPort)...)
	ins = append(ins,
		bpf.RetConstant{Val: 0xffff},
	)
	return ins
}

func FilterEndpoint(proto tcpip.TransportProtocolNumber, src, dst netip.AddrPort) []bpf.Instruction {
	var ins = []bpf.Instruction{
		// load ip version to A
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},
	}

	if src.Addr().Is4() && dst.Addr().Is4() {
		ins = append(ins,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 4, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// store ip header length to reg X
			bpf.LoadMemShift{Off: 0},
		)

		if proto != 0 {
			ins = append(ins,
				// proto
				bpf.LoadAbsolute{Off: 9, Size: 1},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(proto), SkipTrue: 1},
				bpf.RetConstant{Val: 0},
			)
		}
	} else if src.Addr().Is6() && dst.Addr().Is6() {
		ins = append(ins,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// store ip header length to reg X
			bpf.LoadConstant{Dst: bpf.RegX, Val: 40},
		)
		if proto != 0 {
			ins = append(ins,
				bpf.LoadAbsolute{Off: header.IPv6NextHeaderOffset, Size: 1},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(proto), SkipTrue: 1},
				bpf.RetConstant{Val: 0},
			)
		}
	} else {
		return []bpf.Instruction{bpf.RetConstant{Val: 0}}
	}

	ins = append(ins,
		filterAddrs(src.Addr(), dst.Addr())...,
	)

	ins = append(ins,
		filterPorts(src.Port(), dst.Port())...,
	)
	ins = append(ins,
		bpf.RetConstant{Val: 0xffff},
	)
	return ins
}

func filterAddrs(src, dst netip.Addr) (ins []bpf.Instruction) {
	if src.Is4() && dst.Is4() {
		srcInt := binary.BigEndian.Uint32(src.AsSlice())
		dstInt := binary.BigEndian.Uint32(dst.AsSlice())
		ins = append(ins,
			// src addr
			bpf.LoadAbsolute{Off: 12, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcInt, SkipTrue: 1},
			bpf.RetConstant{Val: 0},

			// dst addr
			bpf.LoadAbsolute{Off: 16, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstInt, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
		)
	} else if src.Is6() && dst.Is6() {
		ss := src.AsSlice()
		srcInt1 := binary.BigEndian.Uint32(ss[0:4])
		srcInt2 := binary.BigEndian.Uint32(ss[4:8])
		srcInt3 := binary.BigEndian.Uint32(ss[8:12])
		srcInt4 := binary.BigEndian.Uint32(ss[12:16])
		ds := dst.AsSlice()
		dstInt1 := binary.BigEndian.Uint32(ds[0:4])
		dstInt2 := binary.BigEndian.Uint32(ds[4:8])
		dstInt3 := binary.BigEndian.Uint32(ds[8:12])
		dstInt4 := binary.BigEndian.Uint32(ds[12:16])

		ins = append(ins,
			// src addr1
			bpf.LoadAbsolute{Off: 8, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcInt1, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// src addr2
			bpf.LoadAbsolute{Off: 12, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcInt2, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// src addr3
			bpf.LoadAbsolute{Off: 16, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcInt3, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// src addr4
			bpf.LoadAbsolute{Off: 20, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcInt4, SkipTrue: 1},
			bpf.RetConstant{Val: 0},

			// dst addr1
			bpf.LoadAbsolute{Off: 24, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstInt1, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// dst addr2
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstInt2, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// dst addr3
			bpf.LoadAbsolute{Off: 32, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstInt3, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			// dst addr4
			bpf.LoadAbsolute{Off: 36, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstInt4, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
		)
	}
	return ins
}

// filterPorts filter tcp/udp port, require regX stored iphdr length.
func filterPorts(srcPort, dstPort uint16) []bpf.Instruction {
	return []bpf.Instruction{
		// source port
		bpf.LoadIndirect{Off: 0, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(srcPort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// destination port
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},
	}
}

// iphdrLen store ip header length to reg X
func iphdrLen() []bpf.Instruction {
	return []bpf.Instruction{
		// load ip version to A
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},

		// ipv4
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 4, SkipTrue: 1},
		bpf.LoadMemShift{Off: 0},

		// ipv6
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 1},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 40},
	}
}
