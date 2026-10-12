//go:build js && wasm

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall/js"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

// Forwards a WebSocket from the browser to an app.
//
// The runtime ends the browser's WebSocket in the Durable Object and hands
// over whole messages, not the bytes of the connection, so the hub cannot
// pass the upgraded connection through. It opens its own WebSocket to the
// app over a TLS connection to the app service, like the one a request
// uses, and copies each message across with its type. A close crosses with
// its code and reason in either direction.
//
// While a WebSocket is open, the Go program and its connection to the app
// service stay up, so the Durable Object does not hibernate.

const (
	// appWSMaxMessage is the largest message the hub takes from the app.
	// A larger one closes both sides with 1009. The browser side is
	// limited by the runtime.
	appWSMaxMessage = 16 << 20
	// appWSPing is how often the hub pings the app. The pings and their
	// pongs keep the stream to the app service from closing as idle while
	// the app and the browser are quiet.
	appWSPing = 20 * time.Second
	// appWSCloseWait is how long the hub waits for the app to answer a
	// close from the browser before it drops the connection.
	appWSCloseWait = 5 * time.Second
	// maxCloseReason is the most bytes a close reason may have.
	maxCloseReason = 123
)

// isUpgrade reports whether req asks for a WebSocket.
func (r *request) isUpgrade() bool {
	return r.method == "GET" && strings.EqualFold(r.header["upgrade"], "websocket")
}

// forwardWS opens a WebSocket to the app at host for req, as the user of
// cert, and returns the 101 that hands the browser its end. A dial, TLS or
// handshake failure returns a 502 "app unavailable", and a dial that auth's
// callout refused a 503 "app service busy". An app that refuses the
// upgrade has its status and the start of its body passed on.
func (h *hub) forwardWS(cert tls.Certificate, host string, req *request) *response {
	if err := h.cfg.err("HOST_CA_TLS"); err != nil {
		logf("appws: %v", err)
		return textError("app unavailable", 502)
	}
	d := &websocket.Dialer{
		NetDialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return h.dialAppTLS(ctx, cert)
		},
		HandshakeTimeout: appConnDeadline,
	}
	ctx, cancel := context.WithTimeout(context.Background(), appConnDeadline)
	defer cancel()
	up, resp, err := d.DialContext(ctx, "wss://"+host+req.path+req.query, wsHeader(req, host))
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			logf("appws: app refused the upgrade with %s", resp.Status)
			return &response{status: resp.StatusCode, body: string(body), raw: true}
		}
		logf("appws: %v", err)
		if errors.Is(err, errDialRefused) {
			return textError("app service busy", 503)
		}
		return textError("app unavailable", 502)
	}
	up.SetReadLimit(appWSMaxMessage)
	b := acceptBrowserWS(up)
	res := &response{status: 101, browser: b}
	if p := up.Subprotocol(); p != "" {
		res.add("sec-websocket-protocol", p)
	}
	return res
}

// wsHeader returns the headers of the hub's handshake with the app: those
// of req without the ones that describe the browser's own handshake or the
// hop, Host set to host, and the hub's own session cookies removed. The
// dialer sets the handshake headers itself.
func wsHeader(req *request, host string) http.Header {
	h := http.Header{"Host": {host}}
	for name, value := range req.header {
		switch {
		case name == "host", strings.HasPrefix(name, "cf-"), hopByHop[name],
			name == "sec-websocket-key", name == "sec-websocket-version",
			name == "sec-websocket-extensions":
			continue
		case name == "cookie":
			if kept := stripSPCookies(value); kept != "" {
				h["Cookie"] = []string{kept}
			}
			continue
		}
		h[http.CanonicalHeaderKey(name)] = []string{value}
	}
	if _, ok := h["User-Agent"]; !ok {
		h["User-Agent"] = []string{""}
	}
	return h
}

// browserWS is the browser's WebSocket to an app, with the hub's WebSocket
// to the app behind it.
type browserWS struct {
	id      int
	client  js.Value // the client end, for the 101 response
	out, in js.Value // persistent Uint8Arrays
	inBuf   []byte
	up      *websocket.Conn

	mu   sync.Mutex
	cond *sync.Cond
	// part is the binary message from the browser that has more pieces to
	// come.
	part []byte
	// queue holds the browser's messages that the writer has not sent to
	// the app yet.
	queue []wsMessage
	// closing is true once either side has closed. code and reason are the
	// browser's close, for the writer to send on.
	closing      bool
	fromBrowser  bool
	code         int
	reason       string
	upstreamDone bool
}

type wsMessage struct {
	typ  int
	data []byte
}

var browsers = struct {
	mu sync.Mutex
	m  map[int]*browserWS
}{m: make(map[int]*browserWS)}

func browserOf(id int) *browserWS {
	browsers.mu.Lock()
	defer browsers.mu.Unlock()
	return browsers.m[id]
}

// acceptBrowserWS accepts a new WebSocket pair for the browser and starts
// copying messages between it and up. The response must carry b.client.
func acceptBrowserWS(up *websocket.Conn) *browserWS {
	// IDs come from the connection table, so that worker.mjs, which keeps
	// both kinds in one map, never sees one twice.
	conns.mu.Lock()
	conns.next++
	id := conns.next
	conns.mu.Unlock()
	b := &browserWS{
		id:    id,
		out:   uint8Array.New(outBytes),
		in:    uint8Array.New(inBytes),
		inBuf: make([]byte, inBytes),
		up:    up,
	}
	b.cond = sync.NewCond(&b.mu)
	browsers.mu.Lock()
	browsers.m[id] = b
	browsers.mu.Unlock()
	b.client = glue.acceptBrowser.Invoke(id, b.in)
	go b.readUp()
	go b.writeUp()
	go b.pingUp()
	return b
}

// text queues a text message from the browser. It runs inside the
// JavaScript message event, so it must not block.
func (b *browserWS) text(s string) {
	b.enqueue(wsMessage{websocket.TextMessage, []byte(s)})
}

// binary takes the first n bytes of the in buffer as the next piece of a
// binary message from the browser, which ends with this piece if last is
// true. It runs inside the JavaScript message event, so it must not block.
func (b *browserWS) binary(n int, last bool) {
	js.CopyBytesToGo(b.inBuf[:n], b.in)
	b.mu.Lock()
	b.part = append(b.part, b.inBuf[:n]...)
	if !last {
		b.mu.Unlock()
		return
	}
	data := b.part
	b.part = nil
	b.mu.Unlock()
	b.enqueue(wsMessage{websocket.BinaryMessage, data})
}

func (b *browserWS) enqueue(m wsMessage) {
	b.mu.Lock()
	if !b.closing {
		b.queue = append(b.queue, m)
		b.cond.Broadcast()
	}
	b.mu.Unlock()
}

// browserClosed handles the browser's close, or its error with code 0. The
// writer sends the close on to the app once it has sent the messages before
// it.
func (b *browserWS) browserClosed(code int, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return
	}
	b.closing, b.fromBrowser = true, true
	b.code, b.reason = code, reason
	b.cond.Broadcast()
}

// writeUp sends the browser's messages to the app in order, then the
// browser's close.
func (b *browserWS) writeUp() {
	for {
		b.mu.Lock()
		for len(b.queue) == 0 && !b.closing {
			b.cond.Wait()
		}
		if len(b.queue) == 0 {
			fromBrowser, code, reason := b.fromBrowser, b.code, b.reason
			b.mu.Unlock()
			if fromBrowser {
				b.closeUp(code, reason)
			}
			return
		}
		m := b.queue[0]
		b.queue[0] = wsMessage{}
		b.queue = b.queue[1:]
		b.mu.Unlock()
		if err := b.up.WriteMessage(m.typ, m.data); err != nil {
			logf("appws: write to the app: %v", err)
			b.closeBrowser(websocket.CloseInternalServerErr, "app connection lost")
			b.up.Close()
			return
		}
	}
}

// closeUp sends the browser's close to the app, and drops the connection
// if the app has not answered it within appWSCloseWait.
func (b *browserWS) closeUp(code int, reason string) {
	var payload []byte
	switch {
	case code == 0, code == websocket.CloseAbnormalClosure:
		// The browser went away without a close.
		payload = websocket.FormatCloseMessage(websocket.CloseGoingAway, "")
	case code == websocket.CloseNoStatusReceived:
		payload = websocket.FormatCloseMessage(code, "")
	default:
		payload = websocket.FormatCloseMessage(code, reason)
	}
	b.up.WriteControl(websocket.CloseMessage, payload, time.Now().Add(appWSCloseWait))
	time.AfterFunc(appWSCloseWait, func() { b.up.Close() })
}

// readUp sends the app's messages to the browser, and the app's close.
func (b *browserWS) readUp() {
	defer func() {
		b.mu.Lock()
		b.upstreamDone = true
		b.cond.Broadcast()
		b.mu.Unlock()
		b.up.Close()
	}()
	for {
		typ, data, err := b.up.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			switch {
			case errors.As(err, &ce):
				b.closeBrowser(ce.Code, ce.Text)
			case errors.Is(err, websocket.ErrReadLimit):
				logf("appws: the app sent a message over %d bytes", appWSMaxMessage)
				b.closeBrowser(websocket.CloseMessageTooBig, "message too big")
				b.up.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseMessageTooBig, ""), time.Now().Add(time.Second))
			default:
				if !b.closedByBrowser() {
					logf("appws: read from the app: %v", err)
				}
				b.closeBrowser(websocket.CloseInternalServerErr, "app connection lost")
			}
			return
		}
		if !b.send(typ, data) {
			b.closeBrowser(websocket.CloseInternalServerErr, "send failed")
			return
		}
	}
}

func (b *browserWS) closedByBrowser() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fromBrowser
}

// pingUp pings the app every appWSPing until the app connection ends.
func (b *browserWS) pingUp() {
	t := time.NewTicker(appWSPing)
	defer t.Stop()
	for range t.C {
		b.mu.Lock()
		done := b.upstreamDone || b.closing
		b.mu.Unlock()
		if done {
			return
		}
		if err := b.up.WriteControl(websocket.PingMessage, nil, time.Now().Add(appWSPing)); err != nil {
			return
		}
	}
}

// send sends one message to the browser through the out buffer, in pieces
// that worker.mjs joins. It reports false when the browser's socket is
// gone.
func (b *browserWS) send(typ int, data []byte) bool {
	last := 1
	if typ == websocket.TextMessage {
		last = 2
	}
	for {
		n := min(len(data), outBytes)
		js.CopyBytesToJS(b.out, data[:n])
		kind := 0
		if n == len(data) {
			kind = last
		}
		if !glue.wsSend.Invoke(b.id, b.out, n, kind).Bool() {
			return false
		}
		data = data[n:]
		if kind != 0 {
			return true
		}
	}
}

// closeBrowser closes the browser's socket with code and reason, unless
// the browser closed first. A code that may not be sent, such as 1005,
// closes it without one.
func (b *browserWS) closeBrowser(code int, reason string) {
	b.mu.Lock()
	fromBrowser := b.fromBrowser
	b.closing = true
	b.cond.Broadcast()
	b.mu.Unlock()
	browsers.mu.Lock()
	delete(browsers.m, b.id)
	browsers.mu.Unlock()
	if !sendableCode(code) {
		code = 0
	}
	if fromBrowser {
		// The runtime has the browser's close. The hub answers it with the
		// same code, now that the app has answered too.
		code, reason = b.code, b.reason
		if !sendableCode(code) {
			code = 0
		}
	}
	glue.close.Invoke(b.id, code, truncateUTF8(reason, maxCloseReason))
}

// sendableCode reports whether code may be sent in a close frame.
func sendableCode(code int) bool {
	switch code {
	case 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014:
		return true
	}
	return code >= 3000 && code <= 4999
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
