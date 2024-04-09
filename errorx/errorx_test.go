package errorx_test

import (
	"errors"
	"io"
	"testing"

	"github.com/lysShub/sockit/errorx"
	"github.com/stretchr/testify/require"
)

func Test_ShortBuff(t *testing.T) {
	err := errorx.ShortBuff(1)

	require.True(t, errors.Is(err, io.ErrShortBuffer))
	require.True(t, errorx.Temporary(err))
}
