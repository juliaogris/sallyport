//go:build js && wasm

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// The lazy hub: auth's callout keeps one control socket open, and the hub
// asks it for a stream each time it needs one, so the Durable Object can
// hibernate while nobody uses it.
//
// worker.mjs accepts the control socket with the hibernation API and runs
// its challenge, so the Go program is not needed while the object is idle.
// Go asks for a stream with glue.dial, which sends "dial auth <id>" or
// "dial app <id>" on the one verified control socket. Auth then opens a
// stream with the id in the Sallyport-Stream-Id header. The hub checks the
// id before the upgrade, and uses each id once.
//
// Streams are accepted without hibernation, so the object stays awake while
// one is open. A stream closes after lazyStreamIdle without bytes. The hub
// sends "ack <bytes>" on a stream after each ackEvery bytes it has passed
// on, and the callout keeps at most a window of bytes unacknowledged. When
// the callout opens a stream with the header "Sallyport-Stream: ack", it
// acks the hub's bytes the same way, and the hub keeps at most lazyWindow
// bytes unacknowledged.
//
// The callout may answer a dial with "refuse <id>" on the control socket,
// when worker.mjs has set "Sallyport-Control: refuse" on the control
// socket's upgrade. The dial then fails at once with errDialRefused, and
// the id is used up.
const (
	// streamIDHeader is the request header that carries a stream's id, in
	// lower case as the runtime gives it.
	streamIDHeader = "sallyport-stream-id"
	// maxPendingDials is the number of dials that may wait for their
	// stream. Above this a dial fails at once.
	maxPendingDials = 128
	// lazyDialDeadline is how long a dial waits for its stream.
	lazyDialDeadline = 10 * time.Second
	// lazyStreamIdle closes a stream after this long without bytes in
	// either direction. This also closes an app response that sends nothing
	// for that long, such as a quiet server-sent events stream or a long
	// poll.
	lazyStreamIdle = 30 * time.Second
	// ackEvery is how many bytes a stream passes on between two acks. The
	// sender's window is larger, so it can keep sending while an ack is on
	// its way.
	ackEvery = 256 << 10
	// lazyWindow is the most bytes the hub keeps sent and not acked on a
	// stream whose callout acks them.
	lazyWindow = 1 << 20
	// streamAckHeader is the request header with which auth's callout says
	// that it acks the bytes the hub sends on the stream, with the value
	// "ack".
	streamAckHeader = "sallyport-stream"
)

// lazyHub holds the dials that wait for their stream.
type lazyHub struct {
	dials dialTable[lazyDial]
}

// lazyDial is what a waiting dial gets: its stream, or refused when auth's
// callout answered "refuse <id>". A lazyDial with neither means the hub
// failed to accept the stream.
type lazyDial struct {
	c       *wsConn
	refused bool
}

// serve answers the requests the lazy hub takes: a stream on
// /tunnel/auth?mode=stream. Everything else is 404, because the lazy hub
// has no reverse tunnel and no auth pipe pool, and worker.mjs answers the
// control socket itself.
func (l *lazyHub) serve(req *request) *response {
	q, _ := url.ParseQuery(strings.TrimPrefix(req.query, "?"))
	if req.path != authPipePath || q.Get("mode") != "stream" {
		return textError("not found", 404)
	}
	// Auth's callout sends no Origin, and a browser always sends one.
	if _, ok := req.header["origin"]; ok {
		return textError("origin not allowed", 403)
	}
	ch, ok := l.dials.take(req.header[streamIDHeader])
	if !ok {
		return textError("unknown stream", 404)
	}
	// If accepting the stream panics, the dial still gets an answer, so
	// that it does not wait on ch for good.
	var c *wsConn
	sent := false
	defer func() {
		if sent {
			return
		}
		ch <- lazyDial{}
		if c != nil {
			c.CloseWith(1011, "accept failed")
		}
	}()
	c = acceptWS()
	c.startLazy(req.header[streamAckHeader] == "ack")
	ch <- lazyDial{c: c}
	sent = true
	return &response{status: 101, ws: c}
}

// dial asks auth's callout for a stream of kind auth or app, and waits up
// to lazyDialDeadline or until ctx ends for it. The error is
// errDialRefused when the callout refused the stream.
func (l *lazyHub) dial(ctx context.Context, kind string) (net.Conn, error) {
	started := time.Now()
	var raw [32]byte
	rand.Read(raw[:])
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	ch, ok := l.dials.add(id, maxPendingDials)
	if !ok {
		return nil, fmt.Errorf("%d dials waiting", maxPendingDials)
	}
	if !glue.dial.Invoke(kind, id).Bool() {
		l.dials.cancel(id)
		return nil, fmt.Errorf("auth is not connected")
	}
	d, err := l.dials.wait(ctx, id, ch, lazyDialDeadline, kind)
	switch {
	case err != nil:
	case d.refused:
		err = errDialRefused
	case d.c == nil:
		err = fmt.Errorf("%s stream not accepted", kind)
	}
	result := "paired"
	if err != nil {
		result = "failed"
	}
	logf("lazy: cold %s dial %s in %d ms", kind, result, time.Since(started).Milliseconds())
	if err != nil {
		// A nil *wsConn in the net.Conn would not compare equal to nil.
		return nil, err
	}
	return d.c, nil
}

// refuse ends the dial for id as refused, if it still waits for its stream.
// The id is then used up.
func (l *lazyHub) refuse(id string) {
	if ch, ok := l.dials.take(id); ok {
		ch <- lazyDial{refused: true}
	}
}

// connected reports whether a verified control socket is open.
func (l *lazyHub) connected() bool { return glue.connected.Invoke().Bool() }
