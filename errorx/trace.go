package errorx

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// TraceAttr get github.com/pkg/errors stack trace as slog.Attr
//
// Example:
//
//	slog.Error(err.Error(), xerr.TraceAttr(err))
func TraceAttr(err error) slog.Attr {
	type trace interface{ StackTrace() errors.StackTrace }

	// only hit innermost trace
	var t trace
	for e := err; e != nil; {
		if e1, ok := e.(trace); ok {
			t = e1
		}

		e = errors.Unwrap(e)
	}

	var attrs []slog.Attr
	if t != nil {
		st := t.StackTrace()

		attrs = make([]slog.Attr, 0, len(st)-1)
		for i := 0; i < len(st)-2; i++ {
			attrs = append(attrs, slog.Attr{
				Key:   strconv.Itoa(i),
				Value: position(st[i]),
			})
		}
	}

	// add call self position
	var pcs = make([]uintptr, 1)
	n := runtime.Callers(2, pcs)
	if n == 1 {
		attrs = append(attrs, slog.Attr{
			Key:   strconv.Itoa(len(attrs)),
			Value: position(errors.Frame(pcs[0])),
		})
	}

	return slog.Attr{Key: "trace", Value: slog.GroupValue(attrs...)}
}

func position(f errors.Frame) slog.Value {
	pc := uintptr(f) - 1
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return slog.StringValue("")
	}
	file, line := fn.FileLine(pc)
	file = relpath(file)
	strn := strconv.Itoa(line)

	b := strings.Builder{}
	b.Grow(len(file) + 1 + len(strn))
	b.WriteString(file)
	b.WriteRune(':')
	b.WriteString(strn)
	return slog.StringValue(b.String())
}

var base string

func init() {
	var err error
	base, err = os.Getwd()
	if err == nil {
		base = filepath.Dir(base)
		base = filepath.Dir(base)
		base = filepath.ToSlash(base)
	}
}

func relpath(abs string) string {
	if base == "" {
		return abs
	}

	rel, ok := strings.CutPrefix(abs, base)
	if ok {
		return rel[1:]
	}
	return abs
}
