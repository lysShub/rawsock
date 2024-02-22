package ipstack

type Option func(*Options)

type Options struct {
	CalcIPChecksum bool
	Checksum       uint8
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
}

const (
	_ = iota
	UpdateChecksumWithoutPseudo
	ReCalcChecksum
	NotCalcChecksum
)
