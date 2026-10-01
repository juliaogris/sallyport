//go:build js && wasm

package main

import (
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"
)

// Sizes of the transfer buffers each connection keeps for its whole life.
// A larger write goes out in pieces, and worker.mjs pushes a larger message
// in pieces.
const (
	outBytes = 64 << 10
	inBytes  = 64 << 10
	// A read buffer that grew past this is dropped once it is empty, so one
	// burst does not pin its memory for the life of the connection.
	keepReadBytes = 256 << 10
)

// wsConn is a net.Conn over a Workers WebSocket. Incoming bytes are queued
// without limit: the peer's SSH or TLS flow control bounds them, and on a
// lazy stream the callout's window, which the acks from Read open. Writes are
// coalesced: a write is queued, and a goroutine sends everything queued
// once the writers have yielded, so the TLS records of one SSH packet go
// out as one message.
type wsConn struct {
	id      int
	client  js.Value // the client end, for the 101 response
	out, in js.Value // persistent Uint8Arrays
	inBuf   []byte

	mu     sync.Mutex
	cond   *sync.Cond
	rbuf   []byte
	roff   int
	pend   []byte
	queued bool
	closed bool
	// code is the close code from the peer, or 0.
	code  int
	flush chan struct{}

	// The fields below are for a lazy hub's stream and are guarded by mu,
	// except lastBytes.
	//
	// lazy is true for a lazy hub's stream, which acks the bytes Read has
	// passed on and closes after lazyStreamIdle without bytes.
	lazy bool
	// delivered and acked count the bytes Read has passed on, and those
	// up to the last ack the hub sent.
	delivered, acked int64
	// window is true when the callout acks what the hub sends. Write then
	// keeps at most lazyWindow bytes sent and not acked. sent counts the
	// bytes Write has taken on a lazy stream, and peerAcked those up to the
	// callout's last ack.
	window          bool
	sent, peerAcked int64
	// lastBytes is when bytes last crossed in either direction, in Unix
	// milliseconds. It is atomic, so that checkIdle can read it without mu.
	lastBytes atomic.Int64
	idle      *time.Timer
}

// connTable maps connection IDs to connections for the JavaScript
// callbacks.
type connTable struct {
	mu   sync.Mutex
	next int
	m    map[int]*wsConn
}

var conns = &connTable{m: make(map[int]*wsConn)}

func (t *connTable) get(id int) *wsConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[id]
}

func (t *connTable) remove(id int) {
	t.mu.Lock()
	delete(t.m, id)
	t.mu.Unlock()
}

// acceptWS accepts a new WebSocket pair and returns its server end as a
// connection. The response must carry c.client.
func acceptWS() *wsConn {
	conns.mu.Lock()
	conns.next++
	c := &wsConn{
		id:    conns.next,
		out:   uint8Array.New(outBytes),
		in:    uint8Array.New(inBytes),
		inBuf: make([]byte, inBytes),
		flush: make(chan struct{}, 1),
	}
	c.cond = sync.NewCond(&c.mu)
	conns.m[c.id] = c
	conns.mu.Unlock()
	c.client = glue.accept.Invoke(c.id, c.in)
	go c.flusher()
	return c
}

// pushIn queues the first n bytes of the in buffer, which JavaScript has
// just filled. It runs inside the JavaScript message event, so it must not
// block.
func (c *wsConn) pushIn(n int) {
	js.CopyBytesToGo(c.inBuf[:n], c.in)
	c.lastBytes.Store(time.Now().UnixMilli())
	c.mu.Lock()
	if c.roff == len(c.rbuf) {
		c.rbuf, c.roff = c.rbuf[:0], 0
	}
	c.rbuf = append(c.rbuf, c.inBuf[:n]...)
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *wsConn) remoteClosed(code int) {
	conns.remove(c.id)
	c.mu.Lock()
	c.closed = true
	c.code = code
	c.pend = c.pend[:0]
	if c.idle != nil {
		c.idle.Stop()
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	select {
	case c.flush <- struct{}{}:
	default:
	}
}

func (c *wsConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.roff == len(c.rbuf) && !c.closed {
		c.cond.Wait()
	}
	if c.roff == len(c.rbuf) {
		return 0, io.EOF
	}
	n := copy(b, c.rbuf[c.roff:])
	c.roff += n
	if c.lazy {
		c.lastBytes.Store(time.Now().UnixMilli())
		c.delivered += int64(n)
		if c.delivered-c.acked >= ackEvery {
			c.acked = c.delivered
			glue.sendText.Invoke(c.id, "ack "+strconv.FormatInt(c.delivered, 10))
		}
	}
	if c.roff == len(c.rbuf) {
		c.rbuf, c.roff = c.rbuf[:0], 0
		if cap(c.rbuf) > keepReadBytes {
			c.rbuf = nil
		}
	}
	return n, nil
}

// Write queues b to send. On a stream with a window, it waits for the
// callout's acks while lazyWindow bytes are not acked, and it returns
// net.ErrClosed with the bytes taken so far if the stream closes first.
func (c *wsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for written < len(b) {
		if c.closed {
			return written, net.ErrClosed
		}
		n := len(b) - written
		if c.window {
			room := lazyWindow - (c.sent - c.peerAcked)
			if room <= 0 {
				// The callout acks only what it has received, so send
				// what is queued before waiting.
				c.flushLocked()
				c.cond.Wait()
				continue
			}
			n = int(min(int64(n), room))
		}
		c.pend = append(c.pend, b[written:written+n]...)
		written += n
		if c.lazy {
			c.sent += int64(n)
			c.lastBytes.Store(time.Now().UnixMilli())
		}
		if len(c.pend) >= outBytes {
			c.flushLocked()
		}
	}
	if len(c.pend) > 0 && !c.queued {
		c.queued = true
		select {
		case c.flush <- struct{}{}:
		default:
		}
	}
	return written, nil
}

// peerAck takes the callout's ack text message s, "ack <total>", on a
// stream with a window, and wakes the writers. An ack that does not parse,
// goes backwards or is above the bytes sent closes the stream with 1008.
// Text on a stream without a window is ignored. It runs inside the
// JavaScript message event, so it must not block.
func (c *wsConn) peerAck(s string) {
	c.lastBytes.Store(time.Now().UnixMilli())
	c.mu.Lock()
	if !c.window || c.closed {
		c.mu.Unlock()
		return
	}
	digits, ok := strings.CutPrefix(s, "ack ")
	total, err := strconv.ParseInt(digits, 10, 64)
	if !ok || err != nil || total < c.peerAcked || total > c.sent {
		c.mu.Unlock()
		logf("lazy: bad ack %q, closing the stream", s)
		c.CloseWith(1008, "bad ack")
		return
	}
	c.peerAcked = total
	c.cond.Broadcast()
	c.mu.Unlock()
}

// flushLocked sends everything queued, in messages of at most outBytes.
func (c *wsConn) flushLocked() {
	for off := 0; off < len(c.pend); {
		n := js.CopyBytesToJS(c.out, c.pend[off:min(len(c.pend), off+outBytes)])
		glue.send.Invoke(c.id, c.out, n)
		off += n
	}
	c.pend = c.pend[:0]
	if cap(c.pend) > keepReadBytes {
		c.pend = nil
	}
}

// flusher sends queued writes after the writers yield, until the
// connection closes.
func (c *wsConn) flusher() {
	for range c.flush {
		// Let the goroutines that are ready run first, so that their
		// writes join this message.
		runtime.Gosched()
		c.mu.Lock()
		c.queued = false
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.flushLocked()
		c.mu.Unlock()
	}
}

// Close sends what is queued and closes the WebSocket with code 1000.
func (c *wsConn) Close() error { return c.CloseWith(1000, "closed") }

// CloseWith sends what is queued and closes the WebSocket with the given
// code and reason.
func (c *wsConn) CloseWith(code int, reason string) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.flushLocked()
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	conns.remove(c.id)
	glue.close.Invoke(c.id, code, reason)
	select {
	case c.flush <- struct{}{}:
	default:
	}
	return nil
}

// startLazy makes c a lazy hub's stream: Read acks what it passes on, and
// c closes after lazyStreamIdle without bytes. If window is true, Write
// also waits for the callout's acks. The timer runs only while c is open,
// so an idle hub has none.
func (c *wsConn) startLazy(window bool) {
	c.lastBytes.Store(time.Now().UnixMilli())
	c.mu.Lock()
	c.lazy = true
	c.window = window
	c.idle = time.AfterFunc(lazyStreamIdle, c.checkIdle)
	c.mu.Unlock()
}

// checkIdle closes c if no bytes have crossed for lazyStreamIdle, and
// otherwise checks again when that time would be up.
func (c *wsConn) checkIdle() {
	left := lazyStreamIdle - time.Since(time.UnixMilli(c.lastBytes.Load()))
	if left <= 0 {
		c.mu.Lock()
		logf("lazy: stream idle for %v, closing, %d bytes in (%d acked, %d unread), %d bytes out (%d acked by the callout)",
			lazyStreamIdle, c.delivered+int64(len(c.rbuf)-c.roff), c.acked, len(c.rbuf)-c.roff, c.sent, c.peerAcked)
		c.mu.Unlock()
		c.CloseWith(1000, "idle")
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.idle.Reset(left)
	}
	c.mu.Unlock()
}

// waitClosed returns once either side has closed the connection.
func (c *wsConn) waitClosed() {
	c.mu.Lock()
	for !c.closed {
		c.cond.Wait()
	}
	c.mu.Unlock()
}

// isClosed reports whether either side has closed the connection.
func (c *wsConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *wsConn) LocalAddr() net.Addr              { return wsAddr{} }
func (c *wsConn) RemoteAddr() net.Addr             { return wsAddr{} }
func (c *wsConn) SetDeadline(time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(time.Time) error { return nil }

type wsAddr struct{}

func (wsAddr) Network() string { return "websocket" }
func (wsAddr) String() string  { return "websocket" }

// streamIdle ends a response body that the runtime has not pulled from for
// this long. When the browser goes away, the runtime stops pulling but does
// not always cancel the stream, and the upstream connection would stay
// open for good.
const streamIdle = 30 * time.Second

// bodyStream is a response body that JavaScript pulls from Go. Each chunk
// goes through one persistent Uint8Array.
type bodyStream struct {
	id         int
	js         js.Value
	buf        js.Value
	r          io.ReadCloser
	pulls      chan struct{}
	gone       chan struct{}
	once       sync.Once
	cancelOnce sync.Once
}

type streamTable struct {
	mu   sync.Mutex
	next int
	m    map[int]*bodyStream
}

var streams = &streamTable{m: make(map[int]*bodyStream)}

func (t *streamTable) get(id int) *bodyStream {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[id]
}

// newBodyStream returns a stream that reads r as JavaScript pulls, and
// closes r at the end or when the reader cancels.
func newBodyStream(r io.ReadCloser) *bodyStream {
	streams.mu.Lock()
	streams.next++
	s := &bodyStream{
		id:    streams.next,
		buf:   uint8Array.New(outBytes),
		r:     r,
		pulls: make(chan struct{}, 1),
		gone:  make(chan struct{}),
	}
	streams.m[s.id] = s
	streams.mu.Unlock()
	s.js = glue.stream.Invoke(s.id, s.buf)
	go s.run()
	return s
}

func (s *bodyStream) run() {
	buf := make([]byte, outBytes)
	defer s.end()
	idle := time.NewTimer(streamIdle)
	defer idle.Stop()
	for {
		select {
		case <-s.pulls:
		case <-s.gone:
			return
		case <-idle.C:
			logf("appproxy: response body not read for %v, closing", streamIdle)
			return
		}
		n, err := s.r.Read(buf)
		for n == 0 && err == nil {
			n, err = s.r.Read(buf)
		}
		if err != nil && err != io.EOF {
			logf("appproxy: response body: %v", err)
			glue.chunk.Invoke(s.id, -2, false)
			return
		}
		// The last chunk carries the end with it. The runtime stops pulling
		// once it has Content-Length bytes, so a separate end would never
		// be asked for, and the upstream connection would stay open.
		if n > 0 {
			js.CopyBytesToJS(s.buf, buf[:n])
		}
		glue.chunk.Invoke(s.id, n, err == io.EOF)
		if err == io.EOF {
			return
		}
		// Only the wait for the next pull counts, not a slow upstream.
		idle.Reset(streamIdle)
	}
}

func (s *bodyStream) end() {
	s.once.Do(func() {
		streams.mu.Lock()
		delete(streams.m, s.id)
		streams.mu.Unlock()
		s.r.Close()
	})
}

func (s *bodyStream) pull() {
	select {
	case s.pulls <- struct{}{}:
	default:
	}
}

func (s *bodyStream) cancel() {
	s.cancelOnce.Do(func() { close(s.gone) })
	// The reader may be blocked in Read, so close it now.
	go s.end()
}
