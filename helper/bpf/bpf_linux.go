//go:build linux
// +build linux

package bpf

import (
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func SetRawBPF(raw syscall.RawConn, ins []bpf.Instruction) error {
	var e error
	if err := raw.Control(func(fd uintptr) {
		e = SetBPF(fd, ins)
	}); err != nil {
		return err
	}
	return e
}

func SetBPF(fd uintptr, ins []bpf.Instruction) error {
	// drain buffered packet
	// https://natanyellin.com/posts/ebpf-filtering-done-right/
	err := setBPF(fd, []bpf.Instruction{bpf.RetConstant{Val: 0}})
	if err != nil {
		return err
	}
	var b = make([]byte, 1)
	for {
		n, _, _ := unix.Recvfrom(int(fd), b, unix.MSG_DONTWAIT)
		if n < 0 {
			break
		}
	}

	err = setBPF(fd, ins)
	return err
}

func setBPF(fd uintptr, ins []bpf.Instruction) error {
	var prog *unix.SockFprog
	if rawIns, err := bpf.Assemble(ins); err != nil {
		return err
	} else {
		prog = &unix.SockFprog{
			Len:    uint16(len(rawIns)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&rawIns[0])),
		}
	}

	err := unix.SetsockoptSockFprog(
		int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog,
	)
	return err
}
