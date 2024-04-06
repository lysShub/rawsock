package packet_test

import (
	"testing"

	"github.com/lysShub/sockit/packet"
	"github.com/stretchr/testify/require"
)

func Test_SetHead(t *testing.T) {
	t.Run("SetHead0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetHead(3)

		require.Equal(t, 3, p.Head())
		require.Equal(t, 1, p.Data())
		require.Equal(t, 1, len(p.Bytes()))
		require.Equal(t, 2, p.Tail())
	})
	t.Run("SetHead2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetHead(4)

		require.Equal(t, 4, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 0, len(p.Bytes()))
		require.Equal(t, 2, p.Tail())
	})
	t.Run("SetHead3", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetHead(0)

		require.Equal(t, 0, p.Head())
		require.Equal(t, 4, p.Data())
		require.Equal(t, 4, len(p.Bytes()))
		require.Equal(t, 2, p.Tail())
	})
	t.Run("SetHead4", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetHead(6)

		require.Equal(t, 4, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 0, len(p.Bytes()))
		require.Equal(t, 2, p.Tail())
	})
	t.Run("SetHead5", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetHead(7)

		require.Equal(t, 4, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 0, len(p.Bytes()))
		require.Equal(t, 2, p.Tail())
	})

	t.Run("SetHead6", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetHead(-1)

		require.Equal(t, 0, p.Head())
		require.Equal(t, 4, p.Data())
		require.Equal(t, 4, len(p.Bytes()))
		require.Equal(t, 2, p.Tail())
	})
}

func Test_SetData(t *testing.T) {
	t.Run("SetData0", func(t *testing.T) {

		p := packet.Make(2, 2, 2)
		p.SetData(3)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 3, p.Data())
		require.Equal(t, 3, len(p.Bytes()))
		require.Equal(t, 1, p.Tail())
	})
	t.Run("SetData2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetData(4)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 4, p.Data())
		require.Equal(t, 4, len(p.Bytes()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetData3", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetData(0)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 0, len(p.Bytes()))
		require.Equal(t, 4, p.Tail())
	})
	t.Run("SetData4", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetData(5)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 4, p.Data())
		require.Equal(t, 4, len(p.Bytes()))
		require.Equal(t, 0, p.Tail())
	})

	t.Run("SetData5", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.SetData(-1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 0, len(p.Bytes()))
		require.Equal(t, 4, p.Tail())
	})
}

func Test_Sets(t *testing.T) {
	var ss [][2]int

	values := []int{-1, 0, 1, 2, 3, 4, 5, 6, 7}
	for _, e1 := range values {
		for _, e2 := range values {
			ss = append(ss, [2]int{e1, e2})
		}
	}

	for _, e := range ss {
		p1 := packet.Make(2, 2, 2)
		p1.Sets(e[0], e[1])

		p2 := packet.Make(2, 2, 2)
		p2.SetHead(e[0])
		p2.SetData(e[1])
		require.Equal(t, p2, p1)
	}
}

func Test_AttachN(t *testing.T) {
	t.Run("AttachN0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AttachN(-1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AttachN1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AttachN(0)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})
	t.Run("AttachN2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AttachN(1)

		require.Equal(t, 1, p.Head())
		require.Equal(t, 3, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AttachN3", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AttachN(2)

		require.Equal(t, 0, p.Head())
		require.Equal(t, 4, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AttachN4", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AttachN(3)

		require.Equal(t, packet.DefaulfHead, p.Head())
		require.Equal(t, 5, p.Data())
		require.Equal(t, 2, p.Tail())
	})
}

func Test_Attach(t *testing.T) {
	t.Run("Attach0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Attach(nil)

		require.Equal(t, 2, p.Head())
		require.Equal(t, []byte{0, 0}, p.Bytes())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Attach1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Attach([]byte{0x11})

		require.Equal(t, 1, p.Head())
		require.Equal(t, []byte{0x11, 0, 0}, p.Bytes())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Attach2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Bytes()[0] = 0xff
		p.Attach([]byte{1, 2, 3})

		require.Equal(t, packet.DefaulfHead, p.Head())
		require.Equal(t, []byte{1, 2, 3, 0xff, 0}, p.Bytes())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Attach3", func(t *testing.T) {
		msg := "hello world"
		p := packet.Make().Append([]byte(msg))
		require.Equal(t, msg, string(p.Bytes()))
	})
}

func Test_DetachN(t *testing.T) {
	t.Run("DetachN0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.DetachN(-1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("DetachN1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.DetachN(0)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})
	t.Run("DetachN2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.DetachN(1)

		require.Equal(t, 3, p.Head())
		require.Equal(t, 1, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("DetachN3", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.DetachN(2)

		require.Equal(t, 4, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("DetachN4", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.DetachN(3)

		require.Equal(t, 4, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 2, p.Tail())
	})
}

func Test_Detach(t *testing.T) {
	t.Run("Detach0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Detach(nil)

		require.Equal(t, 2, p.Head())
		require.Equal(t, []byte{0, 0}, p.Bytes())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Detach1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Detach(make([]byte, 1))

		require.Equal(t, 3, p.Head())
		require.Equal(t, 1, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Detach2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Bytes()[0] = 0xff
		d := p.Detach(make([]byte, 3))

		require.Equal(t, 4, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, []byte{0xff, 0}, d)
		require.Equal(t, 2, p.Tail())
	})
}

func Test_AppendN(t *testing.T) {
	t.Run("AppendN0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AppendN(-1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AppendN1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AppendN(0)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})
	t.Run("AppendN2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AppendN(1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 3, p.Data())
		require.Equal(t, 1, p.Tail())
	})

	t.Run("AppendN3", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AppendN(2)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 4, p.Data())
		require.Equal(t, 0, p.Tail())
	})

	t.Run("AppendN4", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.AppendN(3)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 5, p.Data())
		require.Equal(t, packet.DefaulfTail, p.Tail())
	})
}

func Test_Append(t *testing.T) {
	t.Run("Append0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Append(nil)

		require.Equal(t, 2, p.Head())
		require.Equal(t, []byte{0, 0}, p.Bytes())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Append1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Append([]byte{0x11})

		require.Equal(t, 2, p.Head())
		require.Equal(t, []byte{0, 0, 0x11}, p.Bytes())
		require.Equal(t, 1, p.Tail())
	})

	t.Run("Append2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Bytes()[0] = 0xff
		p.Append([]byte{1, 2, 3})

		require.Equal(t, 2, p.Head())
		require.Equal(t, []byte{0xff, 0, 1, 2, 3}, p.Bytes())
		require.Equal(t, packet.DefaulfTail, p.Tail())
	})

	t.Run("Append3", func(t *testing.T) {
		msg := "hello world"
		p := packet.Make().Append([]byte(msg))
		require.Equal(t, msg, string(p.Bytes()))
	})
}

func Test_ReduceN(t *testing.T) {
	t.Run("ReduceN0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.ReduceN(-1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("ReduceN1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.ReduceN(0)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Data())
		require.Equal(t, 2, p.Tail())
	})
	t.Run("ReduceN2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.ReduceN(1)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 1, p.Data())
		require.Equal(t, 3, p.Tail())
	})

	t.Run("ReduceN3", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.ReduceN(2)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 4, p.Tail())
	})

	t.Run("ReduceN4", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.ReduceN(3)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, 4, p.Tail())
	})
}

func Test_Reduce(t *testing.T) {
	t.Run("Reduce0", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Reduce(nil)

		require.Equal(t, 2, p.Head())
		require.Equal(t, []byte{0, 0}, p.Bytes())
		require.Equal(t, 2, p.Tail())
	})

	t.Run("Reduce1", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Reduce(make([]byte, 1))

		require.Equal(t, 2, p.Head())
		require.Equal(t, 1, p.Data())
		require.Equal(t, 3, p.Tail())
	})

	t.Run("Reduce2", func(t *testing.T) {
		p := packet.Make(2, 2, 2)
		p.Bytes()[0] = 0xff
		d := p.Reduce(make([]byte, 3))

		require.Equal(t, 2, p.Head())
		require.Equal(t, 0, p.Data())
		require.Equal(t, []byte{0xff, 0}, d)
		require.Equal(t, 4, p.Tail())
	})
}

func Test_Clone(t *testing.T) {
	p := packet.Make(2, 2, 2)
	p.Bytes()[0], p.Bytes()[1] = 3, 4
	p.Attach([]byte{1, 2})
	p.Append([]byte{5, 6})
	p.Sets(2, 2)

	p1 := p.Clone()
	require.Equal(t, p, p1)
}
