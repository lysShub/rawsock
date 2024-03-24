package tcp

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lysShub/rsocket/test"
	"github.com/stretchr/testify/require"
)

func Test_Listen(t *testing.T) {

	t.Skip("not support")

	t.Run("accept-once", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP(), test.RandPort())

		var cnt atomic.Uint32
		go func() {
			l, err := ListenEth(addr)
			require.NoError(t, err)
			defer l.Close()

			for {
				conn, err := l.Accept()
				require.NoError(t, err)
				conn.Close()
				cnt.Add(1)
			}
		}()
		time.Sleep(time.Second)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			// system tcp dial will retransmit SYN packet
			_, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
			require.Error(t, err)
		}()

		time.Sleep(time.Second * 3)
		cancel()
		require.Equal(t, uint32(1), cnt.Load())
	})
}
