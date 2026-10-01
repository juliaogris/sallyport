//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
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
)

// acceptAuthPipe accepts one WebSocket from auth and runs the challenge on
// it.
func (h *hub) acceptAuthPipe(req *request) *response {
	if err := h.cfg.err("AUTH_CALLOUT_PUBKEY"); err != nil {
		logf("tunnel/auth: %v", err)
		return textError(err.Error(), 500)
	}
	if h.pool.full() {
		logf("tunnel/auth: stream limit reached")
		return textError("too many streams", 503)
	}
	c := acceptWS()
	logf("tunnel/auth: connection accepted")
	t, evicted := h.pool.unverified.admit(maxUnverified, clientKey(req), func() {
		logf("tunnel/auth: closed a socket in the challenge for a newer one")
		c.CloseWith(1008, "too many sockets in the challenge")
	})
	if evicted {
		logf("tunnel/auth: %d sockets in the challenge, closed the busiest client's oldest", maxUnverified)
	}
	go h.challenge(c, t)
	return &response{status: 101, ws: c}
}

// challenge verifies auth's signature on c, then puts c in the pool and
// waits until it closes. It drops t, the socket's place among the sockets
// in the challenge, once c is verified or closed.
func (h *hub) challenge(c *wsConn, t *ticket) {
	defer t.drop()
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
	t.drop()
	if h.pool.push(c) {
		logf("tunnel/auth: %d streams open, closed the oldest waiting one", maxAuthStreams)
	}
	c.waitClosed()
	h.pool.release()
	logf("tunnel/auth: stream closed")
}
