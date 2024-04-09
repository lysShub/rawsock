package errorx

import (
	"io"

	"github.com/pkg/errors"
)

func ShortBuff(dataLen int) error {
	return WrapTemp(errors.WithStack(
		errors.WithMessagef(
			io.ErrShortBuffer, "data len %d", dataLen,
		),
	))
}
