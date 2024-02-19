package relraw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Packet_Attach(t *testing.T) {

	t.Run("Attach/overflow", func(t *testing.T) {
		p := NewPacket(2, 1)
		p.Attach([]byte{1, 2, 3})

		b := p.Data()
		require.Equal(t, []byte{1, 2, 3, 0}, b)
		require.Equal(t, defaulfTail, cap(b)-len(b))
		require.Equal(t, defaulfHead, p.Head())
	})

	t.Run("Attach/overflow2", func(t *testing.T) {

		data := make([]byte, 3)
		data[2] = 55

		p := ToPacket(2, data)
		p.Attach([]byte{1, 2, 3})

		b := p.Data()
		require.Equal(t, []byte{1, 2, 3, 55}, b)
		require.Equal(t, defaulfTail, cap(b)-len(b))
		require.Equal(t, defaulfHead, p.Head())
	})

	t.Run("Attach/align", func(t *testing.T) {
		p := NewPacket(2, 1)
		p.Attach([]byte{1, 2})

		b := p.Data()
		require.Equal(t, []byte{1, 2, 0}, b)
		require.Equal(t, defaulfTail, cap(b)-len(b))
		require.Equal(t, 0, p.Head())
	})
}

func Test_Packet_SetHead(t *testing.T) {

	t.Run("SetHead", func(t *testing.T) {

		p := NewPacket(2, 2, 2)
		p.SetHead(3)

		require.Equal(t, 3, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, 1, p.Tail())
	})
	t.Run("SetHead2", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.SetHead(4)

		require.Equal(t, 4, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetHead3", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.SetHead(6)

		require.Equal(t, 6, p.Head())
		require.Equal(t, 0, p.Len())
		require.Equal(t, 0, len(p.Data()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetHead4", func(t *testing.T) {
		p := NewPacket(2, 2, 2)

		defer func() {
			require.NotNil(t, recover())
		}()
		p.SetHead(7)
	})
}

func Test_Packet_SetData(t *testing.T) {
	t.Run("SetLen", func(t *testing.T) {

		p := NewPacket(2, 2, 2)
		p.SetLen(3)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 3, p.Len())
		require.Equal(t, 3, len(p.Data()))
		require.Equal(t, 1, p.Tail())
	})
	t.Run("SetLen2", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.SetLen(4)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 4, p.Len())
		require.Equal(t, 4, len(p.Data()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetLen3", func(t *testing.T) {
		p := NewPacket(2, 2, 2)

		defer func() {
			require.NotNil(t, recover())
		}()
		p.SetLen(5)
	})
}

func Test_Packet_Sets(t *testing.T) {
	t.Run("SetLen", func(t *testing.T) {

		p := NewPacket(2, 2, 2)
		p.Sets(2, 4)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 4, p.Len())
		require.Equal(t, 4, len(p.Data()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetLen2", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Sets(6, 0)

		require.Equal(t, 6, p.Head())
		require.Equal(t, 0, p.Len())
		require.Equal(t, 0, len(p.Data()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetLen3", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Sets(0, 6)

		require.Equal(t, 0, p.Head())
		require.Equal(t, 6, p.Len())
		require.Equal(t, 6, len(p.Data()))
		require.Equal(t, 0, p.Tail())
	})
	t.Run("SetLen4", func(t *testing.T) {
		p := NewPacket(2, 2, 2)

		defer func() {
			require.NotNil(t, recover())
		}()
		p.Sets(3, 4)
	})
	t.Run("SetLen5", func(t *testing.T) {
		p := NewPacket(2, 2, 2)

		defer func() {
			require.NotNil(t, recover())
		}()
		p.Sets(7, 0)
	})
}

func Test_Packet_AllocTail(t *testing.T) {

	t.Run("AllocTail", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Data()[0] = 9

		alloc := p.AllocTail(1)
		require.False(t, alloc)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, byte(9), p.Data()[0])
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AllocTail2", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Data()[0] = 9

		alloc := p.AllocTail(3)
		require.True(t, alloc)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, byte(9), p.Data()[0])
		require.Equal(t, defaulfTail, p.Tail())
	})
}

func Test_Packet_AllocHead(t *testing.T) {

	t.Run("AllocHead", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Data()[0] = 9

		alloc := p.AllocHead(1)
		require.False(t, alloc)

		require.Equal(t, 2, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, byte(9), p.Data()[0])
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AllocHead2", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Data()[0] = 9

		alloc := p.AllocHead(3)
		require.True(t, alloc)

		require.Equal(t, defaulfHead, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, byte(9), p.Data()[0])
		require.Equal(t, 2, p.Tail())
	})

	t.Run("AllocHead3", func(t *testing.T) {
		p := NewPacket(2, 2, 2)
		p.Data()[0] = 9

		alloc := p.AllocHead(defaulfHead + 1)
		require.True(t, alloc)

		require.Equal(t, defaulfHead+1, p.Head())
		require.Equal(t, 2, p.Len())
		require.Equal(t, 2, len(p.Data()))
		require.Equal(t, byte(9), p.Data()[0])
		require.Equal(t, 2, p.Tail())
	})
}
