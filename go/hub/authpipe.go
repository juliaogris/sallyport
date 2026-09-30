//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"sync"
	"time"
)

// The auth pipe: WebSockets that auth opens to the hub with its callout.
//
// The hub sends a 32-byte nonce. Auth replies with its own nonce and an
// Ed25519 signature over "sallyport/authpipe/v1" || host || hub nonce ||
// auth nonce, where host is the host of the URL auth dialled. The hub
// checks the signature against the pinned key in AUTH_CALLOUT_PUBKEY and
// the host against CALLOUT_HOST. A verified WebSocket waits in the pool
// until the hub takes it. Auth hands the stream to its listener on the
// hub's first message.
const (
	authPipePath      = "/tunnel/auth"
	authPipeDomain    = "sallyport/authpipe/v1"
	nonceBytes        = 32
	challengeDeadline = 10 * time.Second
	// maxAuthStreams is the number of WebSockets the hub keeps, verified
	// or not. Auth opens 8 by default.
	maxAuthStreams = 8
)

// authPool holds the verified streams waiting for the hub, oldest first.
type authPool struct {
	mu    sync.Mutex
	ready []*wsConn
	open  int
}

// take returns the oldest open stream, or nil if there is none.
func (p *authPool) take() *wsConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.ready) > 0 {
		c := p.ready[0]
		p.ready[0] = nil
		p.ready = p.ready[1:]
		if !c.isClosed() {
			return c
		}
	}
	return nil
}

// counts returns the number of open WebSockets from auth, waiting or in
// use, and the number of verified streams waiting.
func (p *authPool) counts() (open, ready int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.ready {
		if !c.isClosed() {
			ready++
		}
	}
	return p.open, ready
}

// acceptAuthPipe accepts one WebSocket from auth and runs the challenge on
// it.
func (h *hub) acceptAuthPipe() *response {
	if err := h.cfg.err("AUTH_CALLOUT_PUBKEY"); err != nil {
		logf("tunnel/auth: %v", err)
		return textError(err.Error(), 500)
	}
	p := h.pool
	p.mu.Lock()
	if p.open >= maxAuthStreams {
		p.mu.Unlock()
		logf("tunnel/auth: stream limit reached")
		return textError("too many streams", 503)
	}
	p.open++
	p.mu.Unlock()
	c := acceptWS()
	logf("tunnel/auth: connection accepted")
	go func() {
		h.challenge(c)
		p.mu.Lock()
		p.open--
		p.mu.Unlock()
	}()
	return &response{status: 101, ws: c}
}

// challenge verifies auth's signature on c, then puts c in the pool and
// waits until it closes.
func (h *hub) challenge(c *wsConn) {
	var nonce [nonceBytes]byte
	rand.Read(nonce[:])
	if _, err := c.Write(nonce[:]); err != nil {
		c.CloseWith(1011, "nonce")
		return
	}
	timer := time.AfterFunc(challengeDeadline, func() {
		logf("tunnel/auth: challenge failed, no reply within %v", challengeDeadline)
		c.CloseWith(1008, "challenge timeout")
	})
	reply := make([]byte, nonceBytes+ed25519.SignatureSize)
	_, err := io.ReadFull(c, reply)
	timer.Stop()
	if err != nil {
		if !c.isClosed() {
			logf("tunnel/auth: challenge failed, bad reply")
		}
		c.CloseWith(1008, "challenge")
		return
	}
	authNonce, sig := reply[:nonceBytes], reply[nonceBytes:]
	msg := make([]byte, 0, len(authPipeDomain)+len(h.cfg.calloutHost)+2*nonceBytes)
	msg = append(msg, authPipeDomain...)
	msg = append(msg, h.cfg.calloutHost...)
	msg = append(msg, nonce[:]...)
	msg = append(msg, authNonce...)
	if !ed25519.Verify(h.cfg.calloutPK, msg, sig) {
		logf("tunnel/auth: challenge failed, bad signature")
		c.CloseWith(1008, "challenge")
		return
	}
	logf("tunnel/auth: stream ready")
	h.pool.mu.Lock()
	h.pool.ready = append(h.pool.ready, c)
	h.pool.mu.Unlock()
	c.waitClosed()
	logf("tunnel/auth: stream closed")
}
