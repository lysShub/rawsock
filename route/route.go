package route

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

type Entry struct {
	// dest subnet
	Dest netip.Prefix

	// nextHop addr, as gateway
	Next netip.Addr

	// src interface index and correspond address, actually one
	// interface can with multiple addresses, just select one.
	Interface uint32
	Addr      netip.Addr

	Metric uint32

	raw Raw
}

func (e Entry) Valid() bool {
	return e.Dest.IsValid() && e.Interface != 0
}

func (e Entry) ifistr() string {
	if !e.Addr.IsValid() {
		return strconv.Itoa(int(e.Interface))
	} else {
		return fmt.Sprintf("%d(%s)", e.Interface, e.Addr.String())
	}
}

type Table []Entry

func (t Table) Sort() {
	sort.Sort(tableSortImpl(t))
}

// Match route longest prefix Match
func (t Table) Match(dst netip.Addr) Entry {
	t.Sort()
	return t.match(dst)
}

func (t Table) match(dst netip.Addr) Entry {
	for _, e := range t {
		if e.Dest.Contains(dst) {
			return e
		}
	}
	return Entry{}
}

func (t Table) MatchRoot(dst netip.Addr) (Entry, error) {
	t.Sort()

	var cnt int
	e := t.matchRoot(dst, &cnt)
	if !e.Valid() {
		if cnt > loopLimit {
			return Entry{}, errors.New("cycle route")
		}
		return Entry{}, errors.WithStack(syscall.ENETUNREACH)
	}
	return e, nil
}

const loopLimit = 64

func (t Table) matchRoot(dst netip.Addr, cnt *int) Entry {
	*cnt = *cnt + 1
	if *cnt > loopLimit {
		return Entry{}
	}

	e := t.match(dst)
	if e.Dest.IsSingleIP() {
		return e
	}
	return t.matchRoot(e.Addr, cnt)
}

func (t Table) String() string {
	const cols = 4
	var (
		es             = []string{"dest", "next", "interface", "metric"}
		maxs [cols]int = [cols]int{len(es[0]), len(es[1]), len(es[2]), len(es[3])}
	)

	for _, e := range t {
		next := e.Next.String()
		if !e.Next.IsValid() {
			next = ""
		}
		for _, str := range []string{
			e.Dest.String(),
			next,
			e.ifistr(),
			strconv.Itoa(int(e.Metric)),
		} {
			es = append(es, str)
			i := (len(es) - 1) % cols
			maxs[i] = max(maxs[i], len(str))
		}
	}
	for i, e := range maxs {
		maxs[i] = e + 4
	}

	var s = &strings.Builder{}
	for i, e := range es {
		fixWrite(s, e, maxs[i%cols])
		if i%cols == 3 {
			s.WriteByte('\n')
		}
	}
	return s.String()
}
func fixWrite(s *strings.Builder, str string, size int) {
	s.WriteString(str)
	n := size - len(str)
	for i := 0; i < n; i++ {
		s.WriteRune(' ')
	}
}

type tableSortImpl Table

func (es tableSortImpl) Len() int { return len(es) }
func (es tableSortImpl) Less(i, j int) bool {
	// require desc
	bi, bj := es[i].Dest.Bits(), es[j].Dest.Bits()
	if bi >= bj {
		if bi == bj {
			return es[i].Metric <= es[j].Metric
		}
		return true
	}
	return false
}
func (es tableSortImpl) Swap(i, j int) { es[i], es[j] = es[j], es[i] }

func GetBestInterface(dst netip.Addr) (entry Entry, err error) {
	if !dst.IsValid() {
		return Entry{}, errors.Errorf("invalid address %s", dst.String())
	}

	var es Table
	if dst.Is4() {
		if es, err = GetTable(); err != nil {
			return Entry{}, err
		}
	} else {
		return Entry{}, errors.New("not support ipv6")
	}

	es.Sort()
	e, err := es.MatchRoot(dst)
	return e, err
}
