//go:build windows
// +build windows

package helper

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/lysShub/rsocket/test/debug"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable   = iphlpapi.NewProc("GetIpForwardTable")
	procGetIpAddrTable      = iphlpapi.NewProc("GetIpAddrTable")
	procGetIpForwardEntry2  = iphlpapi.NewProc("GetIpForwardEntry2")
	procGetIpInterfaceEntry = iphlpapi.NewProc("GetIpInterfaceEntry")
)

// GetIpForwardTable get sorted ip route entries
func GetIpForwardTable(table MibIpForwardTable, size *uint32, order bool) error {
	var pTable, intbool uintptr
	if order {
		intbool = 1
	}
	if len(table) > 0 {
		pTable = uintptr(unsafe.Pointer(unsafe.SliceData(table)))
	}

	r1, _, _ := syscall.SyscallN(
		procGetIpForwardTable.Addr(),
		pTable,
		uintptr(unsafe.Pointer(size)),
		intbool,
	)
	if r1 != 0 {
		return errors.WithStack(syscall.Errno(r1))
	}
	return nil
}

//	typedef struct _MIB_IPFORWARDTABLE {
//	  DWORD            dwNumEntries;
//	  MIB_IPFORWARDROW table[ANY_SIZE];
//	} MIB_IPFORWARDTABLE, *PMIB_IPFORWARDTABLE;
type MibIpForwardTable []byte

func (m MibIpForwardTable) NumEntries() uint32 {
	return binary.NativeEndian.Uint32(m[:4])
}

func (m MibIpForwardTable) MibForwardRows() []MibIpForwardRow {
	rows := unsafe.Slice(
		(*MibIpForwardRow)(unsafe.Pointer(unsafe.SliceData(m[4:]))),
		m.NumEntries(),
	)
	if debug.Debug() {
		if len(m)-4 < int(unsafe.Sizeof(MibIpForwardRow{}))*len(rows) {
			panic("")
		}
	}
	return rows
}

// MIB_IPFORWARDROW
type MibIpForwardRow struct {
	dest      uint32
	mask      uint32
	Policy    uint32
	nextHop   uint32
	IfIndex   uint32
	Type      uint32
	Proto     uint32
	Age       uint32
	NextHopAS uint32
	Metric1   uint32
	Metric2   uint32
	Metric3   uint32
	Metric4   uint32
	Metric5   uint32
}

func (r MibIpForwardRow) DestAddr() netip.Prefix {
	m := binary.NativeEndian.AppendUint32(nil, r.mask)
	ones, _ := net.IPMask(m).Size()

	return netip.PrefixFrom(r.destAddr(), ones)
}

func (r MibIpForwardRow) destAddr() netip.Addr {
	a := binary.NativeEndian.AppendUint32(nil, r.dest)
	return netip.AddrFrom4([4]byte(a))
}

func (r MibIpForwardRow) NextHop() netip.Addr {
	a := binary.NativeEndian.AppendUint32(nil, r.nextHop)
	return netip.AddrFrom4([4]byte(a))
}

func GetIpAddrTable(table MibIpAddrTable, size *uint32, order bool) error {
	var pTable, intbool uintptr
	if order {
		intbool = 1
	}
	if len(table) > 0 {
		pTable = uintptr(unsafe.Pointer(unsafe.SliceData(table)))
	}

	r1, _, _ := syscall.SyscallN(
		procGetIpAddrTable.Addr(),
		pTable,
		uintptr(unsafe.Pointer(size)),
		intbool,
	)
	if r1 != 0 {
		return errors.WithStack(syscall.Errno(r1))
	}
	return nil
}

//	typedef struct _MIB_IPADDRTABLE {
//	  DWORD         dwNumEntries;
//	  MIB_IPADDRROW table[ANY_SIZE];
//	} MIB_IPADDRTABLE, *PMIB_IPADDRTABLE;
type MibIpAddrTable []byte

func (m MibIpAddrTable) NumEntries() uint32 {
	return binary.NativeEndian.Uint32(m[:4])
}

func (m MibIpAddrTable) MibIpAddrRows() []MibIpAddrRow {
	rows := unsafe.Slice(
		(*MibIpAddrRow)(unsafe.Pointer(unsafe.SliceData(m[4:]))),
		m.NumEntries(),
	)
	if debug.Debug() {
		if len(m)-4 < int(unsafe.Sizeof(MibIpAddrRow{}))*len(rows) {
			panic("")
		}
	}
	return rows
}

// MIB_IPADDRROW
type MibIpAddrRow struct {
	addr      uint32
	Index     uint32
	mask      uint32
	BCastAddr uint32
	ReasmSize uint32
	unused1   uint16
	unused2   uint16
}

func (r MibIpAddrRow) Addr() netip.Prefix {
	a := binary.NativeEndian.AppendUint32(nil, r.addr)
	m := binary.NativeEndian.AppendUint32(nil, r.mask)
	ones, _ := net.IPMask(m).Size()

	return netip.PrefixFrom(
		netip.AddrFrom4([4]byte(a)), ones,
	)
}

func GetIpForwardEntry2(row *winipcfg.MibIPforwardRow2) error {
	r1, _, _ := syscall.SyscallN(
		procGetIpForwardEntry2.Addr(),
		uintptr(unsafe.Pointer(row)),
	)
	if r1 == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(r1)
}

func GetIpInterfaceEntry(entry *winipcfg.MibIPInterfaceRow) error {
	r1, _, _ := syscall.SyscallN(
		procGetIpInterfaceEntry.Addr(),
		uintptr(unsafe.Pointer(entry)),
	)
	if r1 == windows.NO_ERROR {
		return nil
	}
	return syscall.Errno(r1)
}
