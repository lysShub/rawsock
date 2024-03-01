package ipstack

import "math/rand"

type Option func(*Options)

type Options struct {
	CalcIPChecksum bool
	Checksum       uint8
	InitID         uint16
}

func (os Options) Unmarshal() Option {
	return func(o *Options) {
		o.CalcIPChecksum = os.CalcIPChecksum
		o.Checksum = os.Checksum
	}
}

var Default = Options{
	Checksum:       ReCalcChecksum,
	CalcIPChecksum: true,
	InitID:         uint16(rand.Uint32()),
}

const (
	_ = iota
	UpdateChecksumWithoutPseudo
	ReCalcChecksum
	NotCalcChecksum
)
