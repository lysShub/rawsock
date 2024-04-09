package errorx

func Temporary(err error) bool {
	e, ok := err.(interface{ Temporary() bool })
	return ok && e.Temporary()
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
