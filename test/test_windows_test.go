package test_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
)

func Test_Create_Tuns(t *testing.T) {
	tup, err := test.CreateTunTuple()
	require.NoError(t, err)
	defer tup.Close()

	var (
		caddr = &net.TCPAddr{IP: tup.Addr1.AsSlice(), Port: 19986}
		saddr = &net.TCPAddr{IP: tup.Addr2.AsSlice(), Port: 8080}
	)

	go func() {
		l, err := net.ListenTCP("tcp", saddr)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.AcceptTCP()
		require.NoError(t, err)
		go io.Copy(conn, conn)
	}()
	time.Sleep(time.Second * 2)

	conn, err := net.DialTCP("tcp", caddr, saddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("hello world"))
	require.NoError(t, err)

	var b = make([]byte, 64)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, string(b[:n]), "hello world")
}
