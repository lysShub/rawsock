package test

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/stretchr/testify/require"
)

type MockConn struct {
	t                require.TestingT
	locAddr, remAddr net.Addr

	in  <-chan []byte
	out chan []byte

	// deadline
	// todo: chan time.Time
	r, w, rw chan struct{}

	closed   bool
	closedMu sync.RWMutex
}

func NewMockConn(
	t require.TestingT,
	clientAddr, serverAddr net.Addr,
) (c, s *MockConn) {

	var a, b = make(chan []byte, 16), make(chan []byte, 16)

	c = &MockConn{
		t:       t,
		locAddr: clientAddr,
		remAddr: serverAddr,

		in:  a,
		out: b,

		r:  make(chan struct{}, 2),
		w:  make(chan struct{}, 2),
		rw: make(chan struct{}, 4),
	}

	s = &MockConn{
		t:       t,
		locAddr: serverAddr,
		remAddr: clientAddr,

		in:  b,
		out: a,

		r:  make(chan struct{}, 2),
		w:  make(chan struct{}, 2),
		rw: make(chan struct{}, 4),
	}

	return c, s
}

var _ net.Conn = (*MockConn)(nil)

func (m *MockConn) Read(b []byte) (n int, err error) {
	select {
	case tmp, ok := <-m.in:
		if !ok {
			return 0, io.EOF
		}
		n = copy(b, tmp)
		return
	case <-m.r:
		return 0, os.ErrDeadlineExceeded
	case <-m.rw:
		return 0, os.ErrDeadlineExceeded
	}
}
func (m *MockConn) Write(b []byte) (n int, err error) {
	m.closedMu.RLock()
	defer m.closedMu.RUnlock()
	if m.closed {
		return 0, net.ErrClosed
	}

	tmp := make([]byte, len(b))
	copy(tmp, b)
	select {
	case m.out <- tmp:
		return len(tmp), nil
	case <-m.w:
		return 0, os.ErrDeadlineExceeded
	case <-m.rw:
		return 0, os.ErrDeadlineExceeded
	}
}
func (m *MockConn) Close() error {
	m.closedMu.Lock()
	defer m.closedMu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.out)
	}
	return nil
}
func (m *MockConn) LocalAddr() net.Addr  { return m.locAddr }
func (m *MockConn) RemoteAddr() net.Addr { return m.remAddr }
func (m *MockConn) SetDeadline(t time.Time) error {
	if time.Now().Before(t) {
		return errors.New("before deadline")
	}

	dur := time.Until(t)
	time.AfterFunc(dur, func() {
		select {
		case m.rw <- struct{}{}:
		default:
		}
	})
	return nil
}
func (m *MockConn) SetReadDeadline(t time.Time) error {
	if time.Now().Before(t) {
		return errors.New("before deadline")
	}

	dur := time.Until(t)
	time.AfterFunc(dur, func() {
		select {
		case m.r <- struct{}{}:
		default:
		}
	})
	return nil
}
func (m *MockConn) SetWriteDeadline(t time.Time) error {
	if time.Now().Before(t) {
		return errors.New("before deadline")
	}

	dur := time.Until(t)
	time.AfterFunc(dur, func() {
		select {
		case m.w <- struct{}{}:
		default:
		}
	})
	return nil
}
