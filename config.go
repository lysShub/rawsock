package rawsock

import (
	"github.com/lysShub/rawsock/helper/ipstack"
)

type Config struct {
	UsedPort bool
	SetGRO   bool
	IPStack  *ipstack.Configs

	DivertPriorty int16
}

type Option func(*Config)

func Options(opts ...Option) *Config {
	var cfg = &Config{
		UsedPort: false,
		SetGRO:   true,
		IPStack:  ipstack.Options(),

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

// Checksum set recv/send tansport packet checksum calcuate mode
// todo: replace by TX checksum offload
func Checksum(opts ...ipstack.Option) Option {
	return func(c *Config) {
		c.IPStack = ipstack.Options(opts...)
	}
}

// SetGRO is set gro to off, deafult true
func SetGRO(set bool) Option {
	return func(c *Config) {
		c.SetGRO = set
	}
}
