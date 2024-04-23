package route

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Entry struct {
	// dest subnet
	Dest netip.Prefix

	// nextHop addr, as gateway
	Next netip.Addr

	// src interface index and correspond address, actually one
	// interface can with multiple addresses, just select one.
	Interface uint32
	Addr      netip.Addr // todo: Addrs

	Metric uint32

	raw EntryRaw
}

func (e Entry) Valid() bool {
	return e.Dest.IsValid() && e.Interface != 0
}

func (e Entry) String() string {
	p := newPrinter()
	e.string(p)
	return p.string()
}

func (e Entry) Equal(entry Entry) bool {
	return e.Valid() && entry.Valid() &&
		e.Dest == entry.Dest &&
		e.Next == entry.Next &&
		e.Interface == entry.Interface &&
		e.Addr == entry.Addr &&
		e.Metric == entry.Metric
}

func (e Entry) string(p *printer) {
	next := e.Next.String()
	if !e.Next.IsValid() {
		next = ""
	}

	var ifstr string
	if !e.Addr.IsValid() {
		ifstr = strconv.Itoa(int(e.Interface))
	} else {
		ifstr = fmt.Sprintf("%d(%s)", e.Interface, e.Addr.String())
	}

	p.append(
		e.Dest.String(), next, ifstr, strconv.Itoa(int(e.Metric)),
	)
}

const printCols = 4

type printer struct {
	maxs  [printCols]int
	elems []string
}

func newPrinter() *printer {
	var p = &printer{
		elems: make([]string, 0, 16),
	}
	p.append(
		"dest", "next", "interface", "metric",
	)
	return p
}

func (p *printer) append(es ...string) {
	for _, e := range es {
		p.elems = append(p.elems, e)

		i := (len(p.elems) - 1) % printCols
		p.maxs[i] = max(p.maxs[i], len(e))
	}
}

func (p *printer) string() string {
	var b = &strings.Builder{}
	for i, e := range p.elems {
		fixWrite(b, e, p.maxs[i%printCols]+4)
		if i%printCols == 3 && i != len(p.elems)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func fixWrite(s *strings.Builder, str string, size int) {
	s.WriteString(str)
	n := size - len(str)
	s.WriteString(strings.Repeat(" ", n))
}
