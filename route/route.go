package route

import (
	"net/netip"
	"sort"
	"syscall"

	"github.com/pkg/errors"
)

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
	var p = newPrinter()
	for _, e := range t {
		e.string(p)
	}
	return p.string()
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

	e, err := es.MatchRoot(dst)
	return e, err
}
