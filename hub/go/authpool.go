package main

import (
	"slices"
	"sync"
)

const (
	// maxAuthStreams is the number of verified WebSockets from auth, waiting
	// or in use, that the hub keeps. Auth opens 8 by default. Above this, a
	// newly verified stream closes the oldest waiting one.
	maxAuthStreams = 8
	// maxAccepted is the number of verified WebSockets, waiting or in use,
	// above which acceptAuthPipe answers 503. Only streams in use can take
	// the count above maxAuthStreams, because push closes waiting ones.
	maxAccepted = 2 * maxAuthStreams
	// maxUnverified is the number of WebSockets in the challenge. Auth opens
	// all its streams at once, so this is twice maxAuthStreams, which leaves
	// room for a few other sockets during auth's burst. Above it, a new
	// socket closes the oldest socket of the client with the most in the
	// challenge, so sockets that never answer cannot keep auth out.
	maxUnverified = 2 * maxAuthStreams
)

// authPool holds the verified streams waiting for the hub, oldest first.
type authPool struct {
	mu    sync.Mutex
	ready []*wsConn
	// open counts the verified WebSockets, waiting or in use, that have not
	// closed.
	open int
	// unverified holds the WebSockets in the challenge.
	unverified pendingSet
}

// full reports whether maxAccepted verified WebSockets are open.
func (p *authPool) full() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.open >= maxAccepted
}

// release counts one verified WebSocket as closed.
func (p *authPool) release() {
	p.mu.Lock()
	p.open--
	p.mu.Unlock()
}

// push adds a verified stream and counts it as open. When more than
// maxAuthStreams WebSockets are then open, it closes the oldest waiting
// stream, unless c is the only one waiting. It returns true if it closed
// one.
func (p *authPool) push(c *wsConn) bool {
	p.mu.Lock()
	p.open++
	p.ready = slices.DeleteFunc(p.ready, (*wsConn).isClosed)
	p.ready = append(p.ready, c)
	var evicted *wsConn
	if p.open > maxAuthStreams && len(p.ready) > 1 {
		evicted = p.ready[0]
		p.ready[0] = nil
		p.ready = p.ready[1:]
	}
	p.mu.Unlock()
	if evicted == nil {
		return false
	}
	evicted.CloseWith(1000, "pipe closed")
	return true
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

// counts returns the number of verified WebSockets from auth, waiting or in
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
