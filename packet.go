package relraw

type Packet struct {
	offset int
	b      []byte
}

func NewPacket(off, n int) *Packet {
	return &Packet{
		offset: off,
		b:      make([]byte, off+n, off+n+defaulfCap),
	}
}

func ToPacket(off int, b []byte) *Packet {
	return &Packet{
		offset: off,
		b:      b,
	}
}

func (p *Packet) Reset(off int) {
	p.offset = off
	p.b = p.b[:0]
}

func (p *Packet) Bytes() []byte {
	return p.b[p.offset:]
}

func (p *Packet) Off() int { return p.offset }
func (p *Packet) Len() int { return len(p.b) - p.offset }

func (p *Packet) SetLen(n int) {
	p.b = p.b[:p.offset+n]
}

func (p *Packet) SetOff(n int) bool {
	if n <= len(p.b) {
		p.offset = n
		return true
	}
	return false
}

func (p *Packet) Attach(a []byte) {
	delta := p.offset - len(a)
	if delta >= 0 {
		p.offset -= copy(p.b[delta:], a)
	} else {
		n := len(p.b) + defaulfOff - delta
		tmp := make([]byte, n, n+defaulfCap)

		i := copy(tmp[defaulfOff:], a)
		copy(tmp[defaulfOff+i:], p.Bytes())

		p.b = tmp
		p.offset = defaulfOff
	}
}

const (
	defaulfOff = 32
	defaulfCap = 16
)
