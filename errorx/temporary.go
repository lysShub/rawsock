package errorx

func Temporary(err error) bool {
	for {
		switch x := err.(type) {
		case interface{ Temporary() bool }:
			return x.Temporary()
		case interface{ Unwrap() error }:
			err = x.Unwrap()
		default:
			return false
		}
	}
}

type temporaryErr struct {
	error
}

func WrapTemp(err error) error {
	if err == nil {
		return nil
	}
	return &temporaryErr{error: err}
}
func (t *temporaryErr) Error() string   { return t.error.Error() }
func (t *temporaryErr) Unwrap() error   { return t.error }
func (t *temporaryErr) Temporary() bool { return true }
