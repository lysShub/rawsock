package route_test

import (
	"fmt"
	"testing"

	"github.com/lysShub/rsocket/route"
	"github.com/stretchr/testify/require"
)

func TestXxxx(t *testing.T) {
	rs, err := route.GetTable()
	require.NoError(t, err)

	fmt.Println(rs.String())
}
