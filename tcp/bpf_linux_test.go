package tcp

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lysShub/relraw"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var createTuns = func() func(n int) ([]netip.Addr, error) {
	var idx atomic.Uint32
	var lip = relraw.LocalAddr()
	return func(n int) ([]netip.Addr, error) {
		var addrs = []netip.Addr{}
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("test%d", idx.Add(1))

			{
				file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
				if err != nil {
					return nil, err
				}

				ifq, err := unix.NewIfreq(name)
				if err != nil {
					return nil, err
				}
				ifq.SetUint32(unix.IFF_TUN | unix.IFF_NO_PI)

				err = unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifq)
				if err != nil {
					return nil, err
				}
			}

			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
			if err != nil {
				return nil, err
			}
			defer unix.Close(fd)

			{ // set flags
				ifq, err := unix.NewIfreq(name)
				if err != nil {
					return nil, err
				}

				ifq.SetUint32(ifq.Uint32() | unix.IFF_UP | unix.IFF_RUNNING)
				if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifq); err != nil {
					return nil, err
				}
			}

			{ // set ip
				var addr = netip.AddrFrom4([4]byte{172, 16, 11, uint8(idx.Load()) + 1})
				if addr == lip {
					return nil, fmt.Errorf("address confilt")
				}
				addrs = append(addrs, addr)

				ifq, err := unix.NewIfreq(name)
				if err != nil {
					return nil, err
				}
				if err = ifq.SetInet4Addr(addr.AsSlice()); err != nil {
					return nil, err
				}

				if err = unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifq); err != nil {
					return nil, err
				}
			}
		}
		return addrs, nil
	}
}()

func Test_Create_Tuns(t *testing.T) {
	addrs, err := createTuns(2)
	require.NoError(t, err)

	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: addrs[0].AsSlice(), Port: 8080})
		require.NoError(t, err)

		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			go func() {
				io.Copy(conn, conn)
			}()
		}
	}()
	time.Sleep(time.Second)

	conn, err := net.DialTCP(
		"tcp",
		&net.TCPAddr{IP: addrs[1].AsSlice(), Port: 19986},
		&net.TCPAddr{IP: addrs[0].AsSlice(), Port: 8080},
	)
	require.NoError(t, err)

	_, err = conn.Write([]byte("hello world"))
	require.NoError(t, err)

	var b = make([]byte, 64)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, "hello world", string(b[:n]))
}

func Test_BPF_Filter(t *testing.T) {
	addrs, err := createTuns(2)
	require.NoError(t, err)
	var (
		saddr = netip.AddrPortFrom(addrs[0], 8080)
		caddr = netip.AddrPortFrom(addrs[1], 19986)
	)

	go func() {
		conn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: caddr.Addr().AsSlice()})
		require.NoError(t, err)
		defer conn.Close()

		var noises = [][]byte{
			buildRawTCP(t, caddr, saddr, 128),

			// noise
			buildRawTCP(t, saddr, caddr, 128),
			buildRawTCP(t, netip.AddrPortFrom(caddr.Addr(), randPort()), saddr, 128),
			buildRawTCP(t, caddr, netip.AddrPortFrom(caddr.Addr(), randPort()), 128),
			buildRawTCP(t,
				netip.AddrPortFrom(caddr.Addr(), randPort()),
				netip.AddrPortFrom(saddr.Addr(), randPort()),
				128,
			),
		}

		for {
			for _, b := range noises {
				_, err := conn.WriteToIP(header.IPv4(b).Payload(), &net.IPAddr{IP: saddr.Addr().AsSlice()})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()

	raw, err := ConnectWithBPF(saddr, caddr)
	require.NoError(t, err)
	defer raw.Close()

	for i := 0; i < 3; i++ {
		var b = make([]byte, 1536)
		n, err := raw.Read(b)
		require.NoError(t, err)
		iphdr := header.IPv4(b[:n])

		tcpHdr := header.TCP(iphdr.Payload())
		require.Equal(t, caddr.Port(), tcpHdr.SourcePort())
		require.Equal(t, saddr.Port(), tcpHdr.DestinationPort())
	}
}

func Test_RawConn_Dial_UsrStack_PingPong(t *testing.T) {
	addrs, err := createTuns(2)
	require.NoError(t, err)

	var (
		cAddr = netip.AddrPortFrom(addrs[0], randPort())
		sAddr = netip.AddrPortFrom(addrs[1], randPort())
	)

	// server
	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: sAddr.Addr().AsSlice(), Port: int(sAddr.Port())})
		require.NoError(t, err)
		defer l.Close()
		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	time.Sleep(time.Second)

	// usr-stack with raw-conn
	var conn net.Conn
	{
		raw, err := ConnectWithBPF(cAddr, sAddr)
		require.NoError(t, err)
		defer raw.Close()
		conn = pingPongWithUserStackClient(t, cAddr.Addr(), raw)
	}

	// client
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, []byte("hello"), b[:n])
}
