//go:build !debug
// +build !debug

package debug

const debug = false

func Debug() bool { return debug }
