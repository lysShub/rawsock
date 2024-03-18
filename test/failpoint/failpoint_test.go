package failpoint_test

import (
	"testing"
	"time"

	"github.com/lysShub/relraw/test/failpoint"
	"github.com/stretchr/testify/require"
)

func Test_Failpoint(t *testing.T) {
	failpoint.Enable(failpoint.FnSleep)
	defer failpoint.Disable(failpoint.FnSleep)

	s := time.Now()
	failpoint.Delay(3)

	require.Greater(t, time.Second*2, time.Since(s))
}
