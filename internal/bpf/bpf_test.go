package bpf

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
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
