//go:build linux
// +build linux

package bpf

import (
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func SetBPF(raw syscall.RawConn, ins []bpf.Instruction) error {
	var prog *unix.SockFprog
	if rawIns, err := bpf.Assemble(ins); err != nil {
		return err
	} else {
		prog = &unix.SockFprog{
			Len:    uint16(len(rawIns)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
		}
	}

	var e error
	if err := raw.Control(func(fd uintptr) {
		e = unix.SetsockoptSockFprog(
			int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog,
		)
	}); err != nil {
		return err
	}

	return e
}
