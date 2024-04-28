package conn

import (
	"fmt"
	"net/netip"
	"syscall"

	"github.com/lysShub/sockit/errorx"
	"github.com/lysShub/sockit/route"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// todo: set MSG_TRUNC flag
func ValidComplete(ip []byte) (iphdrsize uint8, err error) {
	switch header.IPVersion(ip) {
	case 4:
		hdr := header.IPv4(ip)
		if tn := int(hdr.TotalLength()); tn != len(ip) {
			return 0, errorx.ShortBuff(int(tn))
		}
		return hdr.HeaderLength(), nil
	case 6:
		hdr := header.IPv6(ip)
		tn := int(hdr.PayloadLength()) + header.IPv6MinimumSize
		if tn != len(ip) {
			return 0, errorx.ShortBuff(int(tn))
		}
		return header.IPv6MinimumSize, nil
	}
	return 0, errors.New("invalid ip packet")
}

type ErrNotUsedPort int

func (e ErrNotUsedPort) Error() string {
	return fmt.Sprintf("port %d not bind", int(e))
}

// DefaultLocal alloc ip addr for deault-local-addr
func DefaultLocal(laddr, raddr netip.Addr) (netip.Addr, error) {
	if !laddr.IsUnspecified() {
		return laddr, nil
	}

	table, err := route.GetTable()
	if err != nil {
		return netip.Addr{}, errors.WithStack(err)
	}
	entry := table.Match(raddr)
	if !entry.Valid() {
		err = errors.WithMessagef(
			syscall.ENETUNREACH,
			"%s -> %s", laddr.String(), raddr.String(),
		) // tood: use net.OpErr
		return netip.Addr{}, errors.WithStack(err)
	}

	if laddr.IsUnspecified() {
		laddr = entry.Addr
	} else {
		if laddr != entry.Addr {
			err = errors.WithMessagef(
				syscall.EADDRNOTAVAIL, laddr.String(),
			)
			return netip.Addr{}, errors.WithStack(err)
		}
	}
	return laddr, nil
}
