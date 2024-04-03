package route_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/lysShub/sockit/route"
	"github.com/lysShub/sockit/test"
	"github.com/stretchr/testify/require"
)

func Test_GetBestInterface(t *testing.T) {

	t.Run("0.0.0.0", func(t *testing.T) {
		entry, err := route.GetBestInterface(netip.IPv4Unspecified())
		require.NoError(t, err)
		require.Equal(t, test.LocIP(), entry.Dest.Addr())

		expIdx := test.GetIndex(t, test.LocIP())
		require.Equal(t, expIdx, entry.Interface)
	})

	t.Run("127.0.0.1", func(t *testing.T) {
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})

		entry, err := route.GetBestInterface(dst)
		require.NoError(t, err)
		require.Equal(t, int32(1), entry.Interface)

		require.Equal(t, dst, entry.Dest.Addr())
	})

	t.Run("baidu.com", func(t *testing.T) {
		dst := func() netip.Addr {
			ips, err := net.LookupIP("baidu.com")
			require.NoError(t, err)
			for _, ip := range ips {
				if ip.To4() != nil {
					return netip.AddrFrom4([4]byte(ip.To4()))
				}
			}
			panic("")
		}()

		entry, err := route.GetBestInterface(dst)
		require.NoError(t, err)
		require.Equal(t, test.LocIP(), entry.Dest.Addr())

		expIdx := test.GetIndex(t, test.LocIP())
		require.Equal(t, expIdx, entry.Interface)
	})

}
