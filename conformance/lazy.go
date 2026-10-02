package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// StreamIDHeader carries the stream id on a lazy hub's stream request.
const StreamIDHeader = "Sallyport-Stream-Id"

// LazyVars returns the vars of a hub in lazy mode.
func LazyVars() map[string]string {
	v := BaseVars()
	v["HUB_MODE"] = "lazy"
	return v
}

// AppServer serves the test app on the streams it is given, as the app
// service does: TLS with a certificate for the cluster's app SNI, a client
// certificate from the cluster TLS CA required, then HTTP/1.1.
type AppServer struct {
	ln *connListener
}

// NewAppServer starts an app server for handler.
func NewAppServer(p *PKI, handler http.Handler) (*AppServer, error) {
	sni := hex.EncodeToString([]byte(p.Cluster)) + "." + authSNI
	cert, err := p.TLSLeaf(sni, sni)
	if err != nil {
		return nil, err
	}
	ln := newConnListener()
	srv := &http.Server{Handler: handler}
	go srv.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.TLSCAPool,
	}))
	return &AppServer{ln: ln}, nil
}

// Close stops the app server.
func (s *AppServer) Close() { s.ln.Close() }

// DialLazy opens a WebSocket to /tunnel/auth with the given mode and
// request headers, without answering any challenge.
func (h *Hub) DialLazy(ctx context.Context, mode string, header http.Header) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{NetDialContext: h.DialContext, TLSClientConfig: EdgeTLS(), HandshakeTimeout: 20 * time.Second}
	return d.DialContext(ctx, "wss://"+LoginHost+CalloutPath+"?mode="+mode, header)
}

// DialControl opens a control socket and answers the hub's challenge with
// key, or the cluster's callout key if key is nil.
func (h *Hub) DialControl(ctx context.Context, p *PKI, key ed25519.PrivateKey) (*websocket.Conn, error) {
	ws, _, err := h.DialControlResp(ctx, p, key, nil)
	return ws, err
}

// DialControlResp is DialControl with extra request headers, and it also
// returns the upgrade response.
func (h *Hub) DialControlResp(ctx context.Context, p *PKI, key ed25519.PrivateKey, header http.Header) (*websocket.Conn, *http.Response, error) {
	ws, resp, err := h.DialLazy(ctx, "control", header)
	if err != nil {
		if resp != nil {
			return nil, resp, fmt.Errorf("control websocket: %w (status %d)", err, resp.StatusCode)
		}
		return nil, nil, fmt.Errorf("control websocket: %w", err)
	}
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, hubNonce, err := ws.ReadMessage()
	ws.SetReadDeadline(time.Time{})
	if err != nil || len(hubNonce) != NonceBytes {
		ws.Close()
		return nil, resp, fmt.Errorf("control nonce: %v, %d bytes", err, len(hubNonce))
	}
	if key == nil {
		key = p.Callout
	}
	authNonce := make([]byte, NonceBytes)
	rand.Read(authNonce)
	msg := append(append(append([]byte(CalloutDomain), LoginHost...), hubNonce...), authNonce...)
	if err := ws.WriteMessage(websocket.BinaryMessage, append(authNonce, ed25519.Sign(key, msg)...)); err != nil {
		ws.Close()
		return nil, resp, fmt.Errorf("control reply: %w", err)
	}
	return ws, resp, nil
}

// Lazy protocol headers and capability values.
const (
	ControlHeader = "Sallyport-Control"
	StreamHeader  = "Sallyport-Stream"
)

// ValidDialID returns true when id is 43 characters of unpadded base64url
// that encodes 32 bytes, so that it encodes back to the same string.
func ValidDialID(id string) bool {
	if len(id) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == id
}

// RunLazy keeps a control socket open to h, as auth's callout does with
// callout_mode: on_demand, and opens a stream for each dial the hub sends.
// Auth streams go to a's listener, and app streams to app. It redials the
// control socket until ctx ends.
func (a *FakeAuth) RunLazy(ctx context.Context, h *Hub, app *AppServer) {
	go func() {
		for ctx.Err() == nil {
			if err := a.serveControl(ctx, h, app); err != nil && ctx.Err() == nil {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()
}

func (a *FakeAuth) serveControl(ctx context.Context, h *Hub, app *AppServer) error {
	ws, resp, err := h.DialControlResp(ctx, a.pki, nil, nil)
	if err != nil {
		return err
	}
	ctl := &control{ws: ws, refuse: resp.Header.Get(ControlHeader) == "refuse"}
	a.mu.Lock()
	a.sockets[ws] = true
	a.mu.Unlock()
	defer a.drop(ws)
	stop := context.AfterFunc(ctx, func() { ws.Close() })
	defer stop()
	for {
		typ, msg, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if typ != websocket.TextMessage {
			return fmt.Errorf("control message is not text")
		}
		parts := strings.Split(string(msg), " ")
		if len(parts) != 3 || parts[0] != "dial" {
			continue
		}
		if !ValidDialID(parts[2]) {
			a.mu.Lock()
			a.badIDs = append(a.badIDs, parts[2])
			a.mu.Unlock()
			continue
		}
		go a.serveLazyStream(ctx, h, app, ctl, parts[1], parts[2])
	}
}

// control is a verified control socket. Writes from several dials are
// serialized.
type control struct {
	ws     *websocket.Conn
	mu     sync.Mutex
	refuse bool
}

func (c *control) send(text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteMessage(websocket.TextMessage, []byte(text))
}

// LazyDial is how the fake auth answers a dial on its control socket.
type LazyDial int

const (
	// LazyDialServe opens the stream and serves it.
	LazyDialServe LazyDial = iota
	// LazyDialIgnore never opens a stream.
	LazyDialIgnore
	// LazyDialClose opens the stream and closes it at once.
	LazyDialClose
	// LazyDialSilent opens the stream and never sends or reads a byte.
	LazyDialSilent
	// LazyDialGarbage opens the stream and sends bytes that are not TLS.
	LazyDialGarbage
	// LazyDialTwice opens a second stream with the same id, then serves
	// the first.
	LazyDialTwice
	// LazyDialRefuse sends "refuse <id>" when the hub supports it, and
	// otherwise opens no stream.
	LazyDialRefuse
	// LazyDialAckText, LazyDialAckBackwards and LazyDialAckAbove open a
	// stream with upload acks and send a bad ack: not a number, below the
	// last ack, and above the bytes the hub sent.
	LazyDialAckText
	LazyDialAckBackwards
	LazyDialAckAbove
)

// SetLazyDial sets how the fake auth answers the app dials that follow.
func (a *FakeAuth) SetLazyDial(d LazyDial) {
	a.mu.Lock()
	a.lazyDial = d
	a.mu.Unlock()
}

// SetLazyAuthDial sets how the fake auth answers the auth dials that
// follow.
func (a *FakeAuth) SetLazyAuthDial(d LazyDial) {
	a.mu.Lock()
	a.lazyAuthDial = d
	a.mu.Unlock()
}

// SetStreamAcks sets whether new streams ask for upload acks. It is on by
// default, as in auth's callout.
func (a *FakeAuth) SetStreamAcks(on bool) {
	a.mu.Lock()
	a.noStreamAcks = !on
	a.mu.Unlock()
}

// Refused returns the dial ids the fake auth refused.
func (a *FakeAuth) Refused() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.refused...)
}

// BadDialIDs returns the dial ids from the hub that ValidDialID refused.
func (a *FakeAuth) BadDialIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.badIDs...)
}

// AckCloses returns the close code of each stream a bad ack was sent on,
// or 0 when the hub did not close it within 10 s.
func (a *FakeAuth) AckCloses() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.ackCloses...)
}

// Duplicates returns the upgrade status of each second stream with a used
// id, or 101 where the hub accepted one.
func (a *FakeAuth) Duplicates() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.duplicates...)
}

// Dials returns the number of dials the hub has sent on control sockets.
func (a *FakeAuth) Dials() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dials
}

func (a *FakeAuth) serveLazyStream(ctx context.Context, h *Hub, app *AppServer, ctl *control, kind, id string) {
	a.mu.Lock()
	a.dials++
	mode := a.lazyDial
	if kind != "app" {
		mode = a.lazyAuthDial
	}
	acks := !a.noStreamAcks
	a.mu.Unlock()
	switch mode {
	case LazyDialIgnore:
		return
	case LazyDialRefuse:
		if ctl.refuse && ctl.send("refuse "+id) == nil {
			a.mu.Lock()
			a.refused = append(a.refused, id)
			a.mu.Unlock()
		}
		return
	}
	header := http.Header{StreamIDHeader: {id}}
	if acks || mode >= LazyDialAckText {
		header.Set(StreamHeader, "ack")
	}
	ws, _, err := h.DialLazy(ctx, "stream", header)
	if err != nil {
		return
	}
	if mode >= LazyDialAckText {
		a.badAck(ws, mode)
		return
	}
	switch mode {
	case LazyDialClose:
		ws.Close()
		return
	case LazyDialSilent:
		// Hold the stream open until the hub closes it.
		go func() {
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					ws.Close()
					return
				}
			}
		}()
		return
	case LazyDialGarbage:
		ws.WriteMessage(websocket.BinaryMessage, []byte("this is not a TLS record\r\n\r\n"))
		WaitClosed(ws, 30*time.Second)
		ws.Close()
		return
	case LazyDialTwice:
		ws2, resp, err := h.DialLazy(ctx, "stream", http.Header{StreamIDHeader: {id}})
		a.mu.Lock()
		if err == nil {
			a.duplicates = append(a.duplicates, 101)
			ws2.Close()
		} else if resp != nil {
			a.duplicates = append(a.duplicates, resp.StatusCode)
		}
		a.mu.Unlock()
	}
	switch kind {
	case "auth":
		// Auth answers are small, so they never fill the window, and the
		// stream needs no FlowConn. Under wrangler dev, a FlowConn's
		// reader delays the last message of a legacy HTTP answer to the
		// Rust hub, which the real callout does not do. Acks go both ways
		// as on app streams.
		if !a.ln.put(&ackConn{WSConn: NewWSConn(ws), acks: acks}) {
			ws.Close()
		}
	case "app":
		if app == nil || !app.ln.put(newDeadlineConn(newFlowConn(ws, acks))) {
			ws.Close()
		}
	default:
		ws.Close()
	}
}

// badAck reads the first bytes the hub sends on ws, sends the bad ack of
// mode, and records how the hub closes the stream.
func (a *FakeAuth) badAck(ws *websocket.Conn, mode LazyDial) {
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got int
	for got == 0 {
		typ, m, err := ws.ReadMessage()
		if err != nil {
			a.recordAckClose(err)
			return
		}
		if typ == websocket.BinaryMessage {
			got += len(m)
		}
	}
	var acks []string
	switch mode {
	case LazyDialAckText:
		acks = []string{"ack many"}
	case LazyDialAckBackwards:
		acks = []string{fmt.Sprintf("ack %d", got), "ack 0"}
	case LazyDialAckAbove:
		acks = []string{fmt.Sprintf("ack %d", got+1<<20)}
	}
	for _, m := range acks {
		ws.WriteMessage(websocket.TextMessage, []byte(m))
	}
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			a.recordAckClose(err)
			return
		}
	}
}

func (a *FakeAuth) recordAckClose(err error) {
	code := 0
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		code = ce.Code
	}
	a.mu.Lock()
	a.ackCloses = append(a.ackCloses, code)
	a.mu.Unlock()
}

// ackEvery is how many bytes a stream receiver passes on between acks.
const ackEvery = 256 << 10

// maxUnread is the most bytes from the hub that auth's callout holds on a
// lazy stream before it closes the stream. Bytes towards the callout have
// no window.
const maxUnread = 8 << 20

// lazyWindow is the most bytes a lazy stream sender keeps unacknowledged,
// as auth's callout does. The hub acks every 256 KiB.
const lazyWindow = 1 << 20

// FlowConn is a net.Conn over a lazy stream, as auth's callout makes it.
// Binary messages carry stream bytes. The hub sends text "ack <n>" with
// the total bytes it has passed on, and Write keeps at most lazyWindow
// bytes unacknowledged. A reader goroutine reads the WebSocket at all
// times, so acks arrive while nobody calls Read.
type FlowConn struct {
	ws *websocket.Conn
	// acks is true when the stream asked for upload acks, so the conn acks
	// the bytes it passes on, which received counts. fmu serializes
	// WebSocket writes.
	acks     bool
	received int64
	fmu      sync.Mutex
	mu       sync.Mutex
	cond     *sync.Cond
	pending  []byte
	err      error
	sent     int64
	acked    int64
	wmu      sync.Mutex
}

// NewFlowConn wraps ws and starts its reader. It sends no upload acks.
func NewFlowConn(ws *websocket.Conn) *FlowConn { return newFlowConn(ws, false) }

func newFlowConn(ws *websocket.Conn, acks bool) *FlowConn {
	c := &FlowConn{ws: ws, acks: acks}
	c.cond = sync.NewCond(&c.mu)
	go c.readLoop()
	return c
}

func (c *FlowConn) readLoop() {
	for {
		typ, m, err := c.ws.ReadMessage()
		c.mu.Lock()
		if err == nil && typ == websocket.BinaryMessage && len(c.pending)+len(m) > maxUnread {
			// Auth's callout closes a stream with more than maxUnread
			// bytes it has not passed on.
			err = fmt.Errorf("more than %d bytes unread", maxUnread)
			c.fmu.Lock()
			c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "unread limit"), time.Now().Add(time.Second))
			c.fmu.Unlock()
			c.ws.Close()
		}
		if err != nil {
			c.err = err
			c.cond.Broadcast()
			c.mu.Unlock()
			return
		}
		if typ == websocket.TextMessage {
			if n, perr := strconv.ParseInt(strings.TrimPrefix(string(m), "ack "), 10, 64); perr == nil && n >= c.acked {
				c.acked = n
			}
		} else {
			c.pending = append(c.pending, m...)
		}
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

// Read passes on bytes from the hub. With acks, it sends "ack <total>"
// each time the bytes passed on cross a multiple of ackEvery. Reads come
// from one reader, so the acks leave in order.
func (c *FlowConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	for len(c.pending) == 0 {
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		c.cond.Wait()
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	before := c.received
	c.received += int64(n)
	var ack int64
	if c.acks && c.received/ackEvery != before/ackEvery {
		ack = c.received
	}
	c.mu.Unlock()
	if ack > 0 {
		c.writeFrame(websocket.TextMessage, []byte(fmt.Sprintf("ack %d", ack)))
	}
	return n, nil
}

func (c *FlowConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), 64<<10)]
		c.mu.Lock()
		for c.sent-c.acked+int64(len(chunk)) > lazyWindow && c.err == nil {
			c.cond.Wait()
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return written, err
		}
		c.sent += int64(len(chunk))
		c.mu.Unlock()
		if err := c.writeFrame(websocket.BinaryMessage, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

func (c *FlowConn) writeFrame(typ int, b []byte) error {
	c.fmu.Lock()
	defer c.fmu.Unlock()
	return c.ws.WriteMessage(typ, b)
}

// Close sends a close frame before it closes the connection, as auth's
// callout does.
func (c *FlowConn) Close() error {
	c.fmu.Lock()
	c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	c.fmu.Unlock()
	return c.ws.Close()
}
func (c *FlowConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *FlowConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *FlowConn) SetDeadline(t time.Time) error      { return nil }
func (c *FlowConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *FlowConn) SetWriteDeadline(t time.Time) error { return nil }
