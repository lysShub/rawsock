package bpf

import (
	"golang.org/x/net/bpf"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// todo: general bpf

func FilterDstPortAndSynFlag(port uint16) []bpf.Instruction {
	var ins = ipHeaderLen()

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

func FilterSrcPortAndDstPort(srcPort, dstPort uint16) []bpf.Instruction {
	var ins = ipHeaderLen()

	ins = append(ins, []bpf.Instruction{
		// source port
		bpf.LoadIndirect{Off: 0, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(srcPort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		// destination port
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 1},
		bpf.RetConstant{Val: 0},

		bpf.RetConstant{Val: 0xffff},
	}...)
	return ins
}

// ipHeaderLen store ip header length to reg X
func ipHeaderLen() []bpf.Instruction {
	return []bpf.Instruction{
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
}
