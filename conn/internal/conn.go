package conn

import (
	"fmt"

	"github.com/lysShub/sockit/errorx"
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
