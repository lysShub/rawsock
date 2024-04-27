//go:build debug
// +build debug

package debug

const debug = true

// disable:
//
// import "bou.ke/monkey"
//
// monkey.Patch(debug.Debug, func() bool { return false })
//
//go:noinline
func Debug() bool { return debug }
