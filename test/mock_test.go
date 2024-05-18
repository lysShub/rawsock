package test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_P(t *testing.T) {
	p := P()
	require.Equal(p, 1, 2)
	require.True(t, p.Failed())
}
