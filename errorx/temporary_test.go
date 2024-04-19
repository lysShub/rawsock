package errorx

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

type tempErr struct{}

func (t tempErr) Error() string   { return "temp err" }
func (t tempErr) Temporary() bool { return true }

func Test_Temporary(t *testing.T) {
	var e1 = errors.WithMessage(tempErr{}, "temp")
	require.True(t, Temporary(e1))

	var e2 = errors.WithStack(errors.New("error"))
	require.False(t, Temporary(e2))

	var e3 error = nil
	require.False(t, Temporary(e3))
}
