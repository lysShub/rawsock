package config

import (
	"fmt"
	"time"

	"github.com/lysShub/relraw/internal/config/ipstack"
)

type Config struct {
	UsedPort       bool
	MTU            int
	CtxCancelDelay time.Duration
	IPStackCfg     ipstack.Options

	DivertPriorty int16
}

var Default = Config{
	UsedPort:       false,
	MTU:            1536,
	CtxCancelDelay: time.Millisecond * 100,
	IPStackCfg:     ipstack.Default,

	DivertPriorty: 0,
}

type ErrNotUsedPort int

func (e ErrNotUsedPort) Error() string {
	return fmt.Sprintf("port %d not bind", int(e))
}
