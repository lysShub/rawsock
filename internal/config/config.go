package config

import (
	"fmt"
	"time"

	"github.com/lysShub/relraw/internal/config/ipstack"
)

type Config struct {
	UsedPort      bool
	CtxPeriod     time.Duration
	CompleteCheck bool // check ip packet is complete
	IPStackCfg    *ipstack.Options

	DivertPriorty int16
}

func Default() *Config {
	return &Config{
		UsedPort:      false,
		CtxPeriod:     time.Millisecond * 100,
		CompleteCheck: true,
		IPStackCfg:    ipstack.Default(),

		DivertPriorty: 0,
	}
}

type ErrNotUsedPort int

func (e ErrNotUsedPort) Error() string {
	return fmt.Sprintf("port %d not bind", int(e))
}
