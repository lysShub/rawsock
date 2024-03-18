package test_test

import (
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/lysShub/relraw/test"
	"github.com/stretchr/testify/require"
)

func Test_ValidPingPongConn(t *testing.T) {
	var (
		seed = time.Now().UnixNano()
		r    = rand.New(rand.NewSource(seed))
		N    = 0xffff
	)
	t.Log("seed", seed)

	c, s := test.NewMockConn(t, nil, nil)

	ret := make(chan struct{}, 1)
	go func() {
		n, err := io.Copy(s, s)
		require.Equal(t, N, int(n))
		require.NoError(t, err)

		ret <- struct{}{}
	}()

	test.ValidPingPongConn(t, r, c, N)
	require.NoError(t, c.Close())

	<-ret
}
