package relraw

import (
	"time"

	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/config/ipstack"
)

type Option func(*config.Config)

func Options(opts ...Option) *config.Config {
	var cfg = config.Default()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// UsedPort indicate the local port is in-used
func UsedPort() Option {
	return func(c *config.Config) {
		c.UsedPort = true
	}
}

// CtxPeriod set check context cancel period
func CtxPeriod(period time.Duration) Option {
	return func(c *config.Config) {
		if period > 0 {
			c.CtxPeriod = period
		}
	}
}

// Complete valid recv packet is completed
func Complete(check bool) Option {
	return func(c *config.Config) {
		c.CompleteCheck = true
	}
}

// Checksum set recv/send tansport packet checksum calcuate mode
func Checksum(opts ...ipstack.Option) Option {
	return func(c *config.Config) {
		for _, opt := range opts {
			opt(c.IPStackCfg)
		}
	}
}
