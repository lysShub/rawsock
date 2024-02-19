package relraw

import (
	"time"

	"github.com/lysShub/relraw/internal/config"
)

type Opt func(*config.Config)

func Options(opts ...Opt) *config.Config {
	var cfg = config.Default
	for _, opt := range opts {
		opt(&cfg)
	}
	return &cfg
}

func UsedPort() Opt {
	return func(c *config.Config) {
		c.UsedPort = true
	}
}

func MTU(mtu int) Opt {
	return func(c *config.Config) {
		if mtu > 0 {
			c.MTU = mtu
		}
	}
}

func CtxCancelDelay(delay time.Duration) Opt {
	return func(c *config.Config) {
		if delay > 0 {
			c.CtxCancelDelay = delay
		}
	}
}
