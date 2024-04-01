//go:build linux
// +build linux

package helper_test

import (
	"testing"

	"github.com/lysShub/rsocket/helper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func Test_Htons(t *testing.T) {
	a := helper.Htons(unix.ETH_P_IP)
	require.Equal(t, uint16(8), a)
}
