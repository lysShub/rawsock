package route_test

import (
	"fmt"
	"testing"

	"github.com/lysShub/sockit/route"
	"github.com/stretchr/testify/require"
)

func TestXxxx(t *testing.T) {
	rs, err := route.GetTable()
	require.NoError(t, err)

	fmt.Println(rs.String())
}
