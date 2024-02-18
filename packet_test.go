package relraw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Packet(t *testing.T) {

	t.Run("a", func(t *testing.T) {
		p := NewPacket(2, 2)

		require.True(t, p.SetOff(4))
		require.Zero(t, len(p.Bytes()))
	})
}

func Test_Packet_Attach(t *testing.T) {

	t.Run("Attach/overflow", func(t *testing.T) {
		p := NewPacket(2, 1)
		p.Attach([]byte{1, 2, 3})

		b := p.Bytes()
		require.Equal(t, []byte{1, 2, 3, 0}, b)
		require.Equal(t, defaulfCap, cap(b)-len(b))
		require.Equal(t, defaulfOff, p.Off())
	})

	t.Run("Attach/overflow2", func(t *testing.T) {

		data := make([]byte, 3)
		data[2] = 55

		p := ToPacket(2, data)
		p.Attach([]byte{1, 2, 3})

		b := p.Bytes()
		require.Equal(t, []byte{1, 2, 3, 55}, b)
		require.Equal(t, defaulfCap, cap(b)-len(b))
		require.Equal(t, defaulfOff, p.Off())
	})

	t.Run("Attach/align", func(t *testing.T) {
		p := NewPacket(2, 1)
		p.Attach([]byte{1, 2})

		b := p.Bytes()
		require.Equal(t, []byte{1, 2, 0}, b)
		require.Equal(t, defaulfCap, cap(b)-len(b))
		require.Equal(t, 0, p.Off())
	})
}
