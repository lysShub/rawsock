//go:build linux
// +build linux

package raw

import (
	"net"
)

// use net.IPConn
type Conn = net.IPConn
