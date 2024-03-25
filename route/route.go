package route

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/lysShub/rsocket/helper"
	"github.com/pkg/errors"
)

type Table []Entry

// Match route longest prefix Match
func (es Table) Match(dst netip.Addr) Entry {
	for _, e := range es {
		if e.Dest.Contains(dst) {
			return e
		}
	}
	return Entry{}
}

func (es Table) MatchRoot(dst netip.Addr) (Entry, error) {
	var cnt int
	e := es.matchRoot(dst, &cnt)
	if !e.Valid() {
		if cnt > loopLimit {
			return Entry{}, errors.New("cycle route")
		}
		return Entry{}, errors.WithStack(syscall.ENETUNREACH)
	}
	return e, nil
}

const loopLimit = 64

func (es Table) matchRoot(dst netip.Addr, cnt *int) Entry {
	*cnt = *cnt + 1
	if *cnt > loopLimit {
		return Entry{}
	}

	e := es.Match(dst)
	if e.Dest.IsSingleIP() {
		return e
	}
	return es.matchRoot(e.Addr, cnt)
}

type Entry struct {
	Dest    netip.Prefix
	Addr    netip.Addr
	Ifidx   int32
	Metrics int32
}

func (e *Entry) Valid() bool {
	return e != nil && e.Dest.IsValid() && e.Ifidx != 0 && e.Addr.IsValid()
}

func (e *Entry) String() string {
	if !e.Valid() {
		return ""
	}

	return fmt.Sprintf(
		"%s %s %d %d",
		e.Dest.String(), e.Addr.String(), e.Ifidx, e.Metrics,
	)
}

func (e *Entry) Name() (string, error) {
	return helper.IoctlGifname(int(e.Ifidx))
}

func (e *Entry) HardwareAddr() (net.HardwareAddr, error) {
	name, err := e.Name()
	if err != nil {
		return nil, err
	}
	return helper.IoctlGifhwaddr(name)
}

type entriesSortImpl Table

func (es entriesSortImpl) Len() int { return len(es) }
func (es entriesSortImpl) Less(i, j int) bool {
	// require desc
	bi, bj := es[i].Dest.Bits(), es[j].Dest.Bits()

	if bi >= bj {
		if bi == bj {
			return es[i].Metrics <= es[j].Metrics
		}
		return true
	}
	return false
}
func (es entriesSortImpl) Swap(i, j int) { es[i], es[j] = es[j], es[i] }
