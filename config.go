package rawsock

import (
	"time"

	"github.com/lysShub/rawsock/helper/ipstack"
)

type Config struct {
	UsedPort  bool
	CtxPeriod time.Duration
	SetGRO    bool
	IPStack   *ipstack.Configs

	DivertPriorty int16
}

type Option func(*Config)

func Options(opts ...Option) *Config {
	var cfg = &Config{
		UsedPort:  false,
		CtxPeriod: time.Millisecond * 100,
		SetGRO:    false,
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

// Checksum set recv/send tansport packet checksum calcuate mode
// todo: replace by TX checksum offload
func Checksum(opts ...ipstack.Option) Option {
	return func(c *Config) {
		c.IPStack = ipstack.Options(opts...)
	}
}

// SetGRO is disable gro, deafult false(not change)
func SetGRO(set bool) Option {
	return func(c *Config) {
		c.SetGRO = set
	}
}
