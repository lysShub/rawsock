package conn

import (
	"time"

	"github.com/lysShub/rsocket/helper/ipstack"
)

type Config struct {
	UsedPort  bool
	CtxPeriod time.Duration
	NotTrunc  bool
	TSO       bool
	IPStack   *ipstack.Configs

	DivertPriorty int16
}

type Option func(*Config)

func Options(opts ...Option) *Config {
	var cfg = &Config{
		UsedPort:  false,
		CtxPeriod: time.Millisecond * 100,
		NotTrunc:  true,
		TSO:       false,
		IPStack:   ipstack.Options(),

		DivertPriorty: 0,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// UsedPort indicate the local port was bind, default false
func UsedPort() Option {
	return func(c *Config) {
		c.UsedPort = true
	}
}

// CtxPeriod context cancel check period, default 100ms
func CtxPeriod(period time.Duration) Option {
	return func(c *Config) {
		if period > 0 {
			c.CtxPeriod = period
		}
	}
}

// NotTrunc not recv truncated packet, default true
func NotTrunc(v bool) Option {
	return func(c *Config) {
		c.NotTrunc = true
	}
}

// Checksum set recv/send tansport packet checksum calcuate mode
// todo: replace by TX checksum offload
func Checksum(opts ...ipstack.Option) Option {
	return func(c *Config) {
		c.IPStack = ipstack.Options(opts...)
	}
}

// TSO enable/disable TSO, default false
func TSO(enable bool) Option {
	return func(c *Config) {
		c.TSO = enable
	}
}
