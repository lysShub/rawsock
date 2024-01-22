package internal

import "sync"

/*
	这是一个网络数据包缓存，是稠密的。
	用于完全存储某些实现下的数据包，使得支持listen
	是一个根据addr-port 读写ring-buff
*/

// recvBuff
type buff struct {
	expRecvOff int //

	head, size int // head闭, size 可能包含空段

	// 存储原始数据, 长度必须是8的倍数
	//  ring-buff
	b []byte

	// 记录b中对应是否有值, 和b保持同步
	roff int
	r    [][2]int // 左闭 右开

	m  *sync.RWMutex
	wt *sync.Cond
}

func newBuff() *buff {
	var b = &buff{
		head: 0,
		size: 0,
		b:    make([]byte, 1024*4),
	}
	return b
}

func (b *buff) Write(off int, data []byte) {
	n := len(data)
	if !b.inr(off, off+n) {
		return // 过时的Off
	}

	if n+b.size > len(b.b) {
		b.grow()
	}

	// 写入
	h := (len(b.b) + (int(off-b.expRecvOff) + b.head)) % len(b.b)
	m := copy(b.b[h:], data)
	if m != n {
		h = copy(b.b[0:], data[m:])
	} else {
		h += m
	}

	del := int(off-b.expRecvOff) + n
	if del > 0 {
		b.expRecvOff += del
		b.head = h
		b.size += del
	} else {
		println("没有前进")
	}
}

func (b *buff) grow() {
	t := make([]byte, len(b.b)*2)
	if b.head < b.size {
		b.head = copy(t, b.b[:b.head])
		tail := len(b.b) - (b.size - b.head)
		b.head += copy(t[:b.head], b.b[tail:])
	} else {
		copy(t, b.b)
	}
}

func (b *buff) Read(data []byte) (n int) {
	if d := b.otr(n); d <= 0 {
		return 0
	} else {
		// read d  大小的数据
		tail := (len(b.b) + b.head - b.size) % len(b.b)

		n = copy(data[:d], b.b[tail:])
		if n < d {
			n += copy(data[n:d], b.b[0:])
		}

		b.wt.Signal()
		return n
	}
}

func (b *buff) inr(l, r int) bool {
	if l < b.roff {
		return false
	}

	var s int = -1
	for i, e := range b.r {
		if e[0] > r {
			b.r = append(b.r[:s], b.r[i:]...)
			b.r[s] = [2]int{l, r}
			return true
		} else if e[1] < l {
			continue
		} else {
			l = min(l, e[0])
			r = max(r, e[1])
			if s == -1 {
				s = i
			}
		}
	}

	b.r = append(b.r, [2]int{l, r})
	return true
}

func (b *buff) otr(n int) (m int) {
	if b.r[0][0] == b.roff {
		defer func() {
			b.roff += int(m)
			b.r[0][0] += int(m)
		}()

		d := int(b.r[0][1] - b.r[0][0])
		return min(d, n)
	}
	return 0
}
