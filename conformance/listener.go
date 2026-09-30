package conformance

import (
	"errors"
	"net"
	"sync"
)

// connListener is a net.Listener that returns the connections put into it,
// so that an http.Server can serve connections that did not come from a
// socket.
type connListener struct {
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func newConnListener() *connListener {
	return &connListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

// put hands c to the server. It returns false if the listener is closed.
func (l *connListener) put(c net.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, errors.New("listener closed")
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// prefixConn is a net.Conn whose first Read returns prefix.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
