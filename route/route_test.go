package route_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/lysShub/sockit/route"
	"github.com/stretchr/testify/require"
)

func TestXxxx(t *testing.T) {
	rs, err := route.GetTable()
	require.NoError(t, err)

	entry, err := rs.MatchRoot(netip.MustParseAddr("8.8.8.8"))
	require.NoError(t, err)

	fmt.Println(entry.String())
}
