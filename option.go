package relraw

import (
	"time"

	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/config/ipstack"
)

type Option func(*config.Config)

func Options(opts ...Option) *config.Config {
	var cfg = config.Default
	for _, opt := range opts {
		opt(&cfg)
	}
	return &cfg
}

// UsedPort indicate the local port is in-used
func UsedPort() Option {
	return func(c *config.Config) {
		c.UsedPort = true
	}
}

func MTU(mtu int) Option {
	return func(c *config.Config) {
		if mtu > 0 {
			c.MTU = mtu
		}
	}
}

func CtxDelay(delay time.Duration) Option {
	return func(c *config.Config) {
		if delay > 0 {
			c.CtxCancelDelay = delay
		}
	}
}

// Checksum in WriteCtx/InjectCtx, set tcp/udp checksum calcuate mode
func Checksum(opts ...ipstack.Option) Option {
	return func(c *config.Config) {
		for _, opt := range opts {
			opt(&c.IPStackCfg)
		}
	}
}
