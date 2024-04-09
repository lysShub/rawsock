package errorx_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/pkg/errors"

	"github.com/lysShub/sockit/errorx"
)

func Test_Loggeer(t *testing.T) {
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	err := c()

	l.LogAttrs(
		context.Background(), slog.LevelError,
		err.Error(), errorx.TraceAttr(err),
	)

	l.Error(err.Error(), errorx.TraceAttr(err))
}

func c() error {
	e := b()
	if e != nil {
		err := errors.WithStack(errors.New("c-fail"))

		return err
	}

	return nil
}

func b() error {
	e := a()
	if e != nil {
		return errors.WithStack(e)
	}

	return nil
}

func a() error {
	e := errors.New("xxx")
	return errors.WithStack(e)
}
