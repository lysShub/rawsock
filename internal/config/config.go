package config

import (
	"errors"
	"time"
)

type Config struct {
	UsedPort       bool
	MTU            int
	CtxCancelDelay time.Duration

	DivertPriorty int16
}

var Default = Config{
	UsedPort:       false,
	MTU:            1536,
	CtxCancelDelay: time.Millisecond * 100,

	DivertPriorty: 0,
}

var ErrInvalidConfigUsedPort = errors.New("wrong config UsedPor")
