package route_test

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/lysShub/sockit/route"
	"github.com/stretchr/testify/require"
)

func TestXxxx(t *testing.T) {
	rs, err := route.GetTable()
	require.NoError(t, err)

	// entry, err := rs.MatchRoot(netip.MustParseAddr("8.8.8.8"))
	// require.NoError(t, err)
	fmt.Println(rs.String())
}

func Test_Match(t *testing.T) {
	tb := unmarshal(t, table)

	t.Run("1", func(t *testing.T) {
		e := tb.Match(netip.MustParseAddr("8.8.8.8"))
		require.True(t, e.Valid())
		require.Equal(t, uint32(2), e.Interface)
	})

	t.Run("2", func(t *testing.T) {
		e := tb.Match(netip.MustParseAddr("172.24.128.1"))
		require.True(t, e.Valid())
		require.Equal(t, uint32(62), e.Interface)
	})

	t.Run("3", func(t *testing.T) {
		e := tb.Match(netip.MustParseAddr("172.24.131.26"))
		require.True(t, e.Valid())
		require.Equal(t, uint32(62), e.Interface)
	})
}

func Test_Loopback(t *testing.T) {
	tb := unmarshal(t, table)

	t.Run("1", func(t *testing.T) {
		lo := tb.Loopback(netip.MustParseAddr("192.168.43.35"))
		require.True(t, lo)
	})

	t.Run("2", func(t *testing.T) {
		lo := tb.Loopback(netip.MustParseAddr("8.8.8.8"))
		require.False(t, lo)
	})

	t.Run("3", func(t *testing.T) {
		lo := tb.Loopback(netip.MustParseAddr("172.24.128.1"))
		require.True(t, lo)
	})

	t.Run("4", func(t *testing.T) {
		lo := tb.Loopback(netip.MustParseAddr("172.24.131.26"))
		require.False(t, lo)
	})

	t.Run("5", func(t *testing.T) {
		lo := tb.Loopback(netip.MustParseAddr("127.0.0.1"))
		require.True(t, lo)
	})
}

func Test_unmarshal(t *testing.T) {
	t.Run("construct", func(t *testing.T) {
		t1 := unmarshal(t, table)
		str := t1.String()
		exp := strings.Trim(table, "\n")
		require.Equal(t, exp, str)
	})

	t.Run("system", func(t *testing.T) {
		t1, err := route.GetTable()
		require.NoError(t, err)

		t2 := unmarshal(t, t1.String())

		for i, e := range t1 {
			require.True(t, e.Equal(t2[i]))
		}
	})
}

const table = `
dest                  next            interface            metric    
0.0.0.0/0             192.168.43.1    2(192.168.43.35)     55        
224.0.0.0/4                           12                   261       
224.0.0.0/4                           62(172.24.128.1)     271       
224.0.0.0/4                           49(192.168.208.1)    271       
224.0.0.0/4                           24                   281       
224.0.0.0/4                           23                   281       
224.0.0.0/4                           2(192.168.43.35)     311       
224.0.0.0/4                           1(127.0.0.1)         331       
224.0.0.0/4                           18(172.25.112.1)     5256      
127.0.0.0/8                           1(127.0.0.1)         331       
172.24.128.0/20                       62(172.24.128.1)     271       
192.168.208.0/20                      49(192.168.208.1)    271       
172.25.112.0/20                       18(172.25.112.1)     5256      
192.168.43.0/24                       2(192.168.43.35)     311       
255.255.255.255/32                    12                   261       
172.24.128.1/32                       62(172.24.128.1)     271       
255.255.255.255/32                    62(172.24.128.1)     271       
192.168.223.255/32                    49(192.168.208.1)    271       
192.168.208.1/32                      49(192.168.208.1)    271       
172.24.143.255/32                     62(172.24.128.1)     271       
255.255.255.255/32                    49(192.168.208.1)    271       
255.255.255.255/32                    23                   281       
255.255.255.255/32                    24                   281       
255.255.255.255/32                    2(192.168.43.35)     311       
192.168.43.35/32                      2(192.168.43.35)     311       
192.168.43.255/32                     2(192.168.43.35)     311       
127.0.0.1/32                          1(127.0.0.1)         331       
127.255.255.255/32                    1(127.0.0.1)         331       
255.255.255.255/32                    1(127.0.0.1)         331       
172.25.112.1/32                       18(172.25.112.1)     5256      
172.25.127.255/32                     18(172.25.112.1)     5256      
255.255.255.255/32                    18(172.25.112.1)     5256      
`

func unmarshal(t require.TestingT, str string) route.Table {
	str = strings.TrimSpace(str)
	ss := strings.Split(str, "\n")
	for i, e := range ss {
		ss[i] = strings.TrimSpace(e)
	}
	var (
		i1  = strings.Index(ss[0], "dest")
		i2  = strings.Index(ss[0], "next")
		i3  = strings.Index(ss[0], "interface")
		i4  = strings.Index(ss[0], "metric")
		get = func(s string) string {
			for i, e := range s {
				if e == ' ' {
					return s[:i]
				}
			}
			return s
		}
	)

	var table route.Table
	for _, e := range ss[1:] {
		row := route.Entry{}
		row.Dest = netip.MustParsePrefix(get(e[i1:]))
		if s := get(e[i2:]); s != "" {
			row.Next = netip.MustParseAddr(s)
		}

		s := get(e[i3:])
		var idx, addr string
		if ss := strings.Split(s, "("); len(ss) > 1 {
			idx = ss[0]
			addr = strings.Trim(ss[1], ")")
		} else {
			idx = s
		}
		v, err := strconv.Atoi(idx)
		require.NoError(t, err)
		row.Interface = uint32(v)
		if addr != "" {
			row.Addr = netip.MustParseAddr(addr)
		}

		v, err = strconv.Atoi(e[i4:])
		require.NoError(t, err)
		row.Metric = uint32(v)

		table = append(table, row)
	}

	return table
}
