package failpoint

import (
	"path/filepath"
	"time"

	"github.com/lysShub/relraw/test"
	"github.com/pingcap/failpoint"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

//go:generate failpoint-ctl enable

const (
	pkgdir = "github.com/lysShub/relraw/test/failpoint"

	FnValidIP  Fpname = "ValidIP"
	FnValidTCP Fpname = "ValiTCP"
	FnSleep    Fpname = "Sleep"
)

type Fpname string

func Enable(fpname Fpname) error {
	return failpoint.Enable(filepath.Join(pkgdir, string(fpname)), "off")
}

func Disable(fpname Fpname) error {
	return failpoint.Disable(filepath.Join(pkgdir, string(fpname)))
}

func ValidIP(ip []byte) {
	failpoint.Inject(string(FnValidIP), func() {
		test.ValidIP(test.T(), ip)
	})
}

func ValidTCP(tcp header.TCP, pseudoSum1 uint16) {
	failpoint.Inject(string(FnValidTCP), func() {
		test.ValidTCP(test.T(), tcp, pseudoSum1)
	})
}

func Delay(secs int) {
	failpoint.Inject(string(FnSleep), func() {
		time.Sleep(time.Second * time.Duration(secs))
	})
}
