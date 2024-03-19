//go:build debug
// +build debug

package debug

const debug = true

//go:noinline
func Debug() bool { return debug }
