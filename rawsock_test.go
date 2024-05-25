package rawsock_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Gofmt(t *testing.T) {
	cmd := exec.Command("gofmt", "-l", "-w", `.`)
	out, err := cmd.CombinedOutput()

	require.NoError(t, err)
	require.Empty(t, string(out))
}
