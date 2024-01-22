package internal

import (
	"io"
)

// todo:

// 可能只会并发读取

type ringHeap struct {
	b          []byte
	head, size int // head 开
}

// alloc 使得可以稠密, 为nil表示分配失败，用put
func (h *ringHeap) alloc(n int) []byte {
	return nil
}

func (h *ringHeap) releaseTail(n int) {

}

const lenSize = 2

func (h *ringHeap) put(b []byte) error {
	n, m := len(b), len(h.b)

	if n+h.size+lenSize > len(h.b) {
		return io.ErrShortBuffer
	}

	if h.head+n+lenSize < m {
		h.b[h.head] = byte(n >> 8)
		h.b[h.head+1] = byte(n)
		copy(h.b[h.head+2:], b)
	} else {
		h.b[h.head%m] = byte(n >> 8)
		h.b[(h.head+1)%m] = byte(n)
		h.head = (h.head + 2) % m

		n1 := copy(h.b[h.head:], b)
		if n1 != n {
			h.head = copy(h.b[0:], b[n1:])
		}
	}
	h.size += n + lenSize

	return nil
}

func (h *ringHeap) pop(b []byte) (n int, err error) {
	m := len(h.b)
	tail := (h.head - h.size) % m

	n = int(uint16(h.b[tail])<<8 + uint16(h.b[(tail+1)%m]))
	h.size -= n + lenSize
	if n > len(b) {
		n, err = len(b), io.ErrShortBuffer
	}
	b = b[:n]

	n1 := copy(b, h.b[(tail+2)%m:])
	if n1 < n {
		copy(b[n1:], h.b[0:])
	}

	return
}
