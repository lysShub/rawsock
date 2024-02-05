package relraw

import "github.com/lysShub/relraw/internal/config"

type Opt func(*config.Config)

func Options(opts ...Opt) *config.Config {
	var cfg = config.Default
	for _, opt := range opts {
		opt(&cfg)
	}
	return &cfg
}

var UsedPort Opt = func(cfg *config.Config) {
	cfg.UsedPort = true
}

func MTU(mtu int) Opt {
	return func(c *config.Config) {
		c.MTU = mtu
	}
}
