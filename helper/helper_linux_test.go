//go:build linux
// +build linux

package helper_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/lysShub/sockit/helper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func Test_Htons(t *testing.T) {
	a := helper.Htons(unix.ETH_P_IP)
	require.Equal(t, uint16(8), a)
}

func Test_IoctlTSO(t *testing.T) {
	ifi := "lo"
	var on = func() bool {
		msg, err := exec.Command("ethtool", "-k", ifi).CombinedOutput()
		require.NoError(t, err)
		rows := strings.Split(string(msg), "\n")
		for _, e := range rows {
			if strings.Contains(e, "tcp-segmentation-offload") {
				return strings.Contains(e, " on")
			}
		}
		panic("")
	}

	init := on()
	defer func() { helper.IoctlTSO(ifi, !init) }()

	err := helper.IoctlTSO(ifi, !init)
	require.NoError(t, err)
	o := on()
	fmt.Println(o)
	require.Equal(t, !init, o)
}
