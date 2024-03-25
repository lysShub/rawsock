package conn

import (
	"fmt"
	"time"

	"github.com/lysShub/rsocket/helper/ipstack"
)

type Option func(*Config)

func Options(opts ...Option) *Config {
	var cfg = &Config{
		UsedPort:      false,
		CtxPeriod:     time.Millisecond * 100,
		CompleteCheck: true,
		IPStack:       ipstack.Options(),

		DivertPriorty: 0,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// UsedPort indicate the local port is in-used
func UsedPort() Option {
	return func(c *Config) {
		c.UsedPort = true
	}
}

// CtxPeriod set check context cancel period
func CtxPeriod(period time.Duration) Option {
	return func(c *Config) {
		if period > 0 {
			c.CtxPeriod = period
		}
	}
}

// Complete valid recv packet is completed
func Complete(check bool) Option {
	return func(c *Config) {
		c.CompleteCheck = true
	}
}

// Checksum set recv/send tansport packet checksum calcuate mode
func Checksum(opts ...ipstack.Option) Option {
	return func(c *Config) {
		c.IPStack = ipstack.Options(opts...)
	}
}

type Config struct {
	UsedPort      bool
	CtxPeriod     time.Duration
	CompleteCheck bool // check ip packet is complete
	IPStack       *ipstack.Configs

	DivertPriorty int16
}

type ErrNotUsedPort int

func (e ErrNotUsedPort) Error() string {
	return fmt.Sprintf("port %d not bind", int(e))
}
