package ipstack

type Option func(*Configs)

func Options(opts ...Option) *Configs {
	cfg := &Configs{
		checksum:       reCalcChecksum,
		calcIPChecksum: true,
	}
	for _, e := range opts {
		e(cfg)
	}
	return cfg
}

// UpdateChecksum update tcp/udp checksum, the old
// checksum is without-pseudo-checksum
func UpdateChecksum(o *Configs) {
	o.checksum = updateChecksumWithoutPseudo
}

// ReCalcChecksum re-calculate tcp/udp checksum
func ReCalcChecksum(o *Configs) {
	o.checksum = reCalcChecksum
}

// NotCalcChecksum not change tcp/udp checksum
func NotCalcChecksum(o *Configs) {
	o.checksum = notCalcChecksum
}

// NotCalcIPChecksum not set ip4 checksum
func NotCalcIPChecksum(o *Configs) {
	o.calcIPChecksum = false
}

type Configs struct {
	calcIPChecksum bool
	checksum       uint8
}

func (os Configs) Unmarshal() Option {
	return func(o *Configs) {
		o.calcIPChecksum = os.calcIPChecksum
		o.checksum = os.checksum
	}
}

const (
	_ = iota
	updateChecksumWithoutPseudo
	reCalcChecksum
	notCalcChecksum
)
