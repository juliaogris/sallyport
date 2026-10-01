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
// on, and the sender keeps at most a window of bytes unacknowledged.
const (
	// streamIDHeader is the request header that carries a stream's id, in
	// lower case as the runtime gives it.
	streamIDHeader = "sallyport-stream-id"
	// maxPendingDials is the number of dials that may wait for their
	// stream. Above this a dial fails at once.
	maxPendingDials = 32
	// lazyDialDeadline is how long a dial waits for its stream.
	lazyDialDeadline = 10 * time.Second
	// lazyStreamIdle closes a stream after this long without bytes in
	// either direction.
	lazyStreamIdle = 30 * time.Second
	// ackEvery is how many bytes a stream passes on between two acks. The
	// sender's window is larger, so it can keep sending while an ack is on
	// its way.
	ackEvery = 256 << 10
)

// lazyHub holds the dials that wait for their stream.
type lazyHub struct {
	dials dialTable[*wsConn]
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
	c := acceptWS()
	c.startLazy()
	ch <- c
	return &response{status: 101, ws: c}
}

// dial asks auth's callout for a stream of kind auth or app, and waits up
// to lazyDialDeadline or until ctx ends for it.
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
	timer := time.NewTimer(lazyDialDeadline)
	defer timer.Stop()
	var c *wsConn
	var err error
	select {
	case c = <-ch:
	case <-timer.C:
		err = fmt.Errorf("no %s stream within %v", kind, lazyDialDeadline)
	case <-ctx.Done():
		err = fmt.Errorf("%s dial: %w", kind, ctx.Err())
	}
	// A stream that arrived as the dial gave up is used.
	if err != nil && !l.dials.cancel(id) {
		c, err = <-ch, nil
	}
	result := "paired"
	if err != nil {
		result = "failed"
	}
	logf("lazy: cold %s dial %s in %d ms", kind, result, time.Since(started).Milliseconds())
	if err != nil {
		return nil, err
	}
	return c, nil
}

// connected reports whether a verified control socket is open.
func (l *lazyHub) connected() bool { return glue.connected.Invoke().Bool() }
