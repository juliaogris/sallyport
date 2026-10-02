package conformance

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
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

// deadlineConn gives a conn without read deadlines, such as an SSH channel
// or a lazy stream, a working SetReadDeadline. A goroutine reads one chunk
// ahead, and Read waits on that chunk until the deadline. net/http needs
// this for Hijack, which ends the server's background read with a read
// deadline in the past. The goroutine reads the next chunk only once Read
// has taken the last one, so that a lazy stream acks only the bytes the
// app has read.
type deadlineConn struct {
	net.Conn
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	err      error
	deadline time.Time
	timer    *time.Timer
}

func newDeadlineConn(c net.Conn) *deadlineConn {
	d := &deadlineConn{Conn: c}
	d.cond = sync.NewCond(&d.mu)
	go d.readLoop()
	return d
}

func (d *deadlineConn) readLoop() {
	b := make([]byte, 64<<10)
	for {
		n, err := d.Conn.Read(b)
		d.mu.Lock()
		d.buf = append(d.buf, b[:n]...)
		if err != nil {
			d.err = err
		}
		d.cond.Broadcast()
		for len(d.buf) > 0 && d.err == nil {
			d.cond.Wait()
		}
		d.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (d *deadlineConn) Read(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.buf) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if !d.deadline.IsZero() && !time.Now().Before(d.deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		d.cond.Wait()
	}
	n := copy(b, d.buf)
	d.buf = d.buf[n:]
	if len(d.buf) == 0 {
		d.cond.Broadcast()
	}
	return n, nil
}

func (d *deadlineConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadline = t
	if d.timer != nil {
		d.timer.Stop()
	}
	if !t.IsZero() {
		d.timer = time.AfterFunc(time.Until(t), func() {
			d.mu.Lock()
			d.cond.Broadcast()
			d.mu.Unlock()
		})
	}
	d.cond.Broadcast()
	return nil
}

func (d *deadlineConn) SetDeadline(t time.Time) error { return d.SetReadDeadline(t) }
