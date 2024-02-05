package config

import "errors"

type Config struct {
	UsedPort bool
	MTU      int

	DivertPriorty int16
}

var Default = Config{
	UsedPort: false,
	MTU:      1536,

	DivertPriorty: 0,
}

var ErrInvalidConfigUsedPort = errors.New("wrong config UsedPor")
