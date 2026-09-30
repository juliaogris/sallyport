package main

import (
	"slices"
	"sync"
)

const (
	// maxAuthStreams is the number of open WebSockets from auth, waiting or
	// in use, that the hub keeps. Auth opens 8 by default.
	maxAuthStreams = 8
	// maxAccepted is the number of WebSockets the hub accepts, verified or
	// not. Above maxAuthStreams, a newly verified stream closes the oldest
	// waiting one. A waiting stream whose auth went away without closing it
	// looks open, and without this it would hold its place forever.
	maxAccepted = 2 * maxAuthStreams
)

// authPool holds the verified streams waiting for the hub, oldest first.
type authPool struct {
	mu    sync.Mutex
	ready []*wsConn
	// open counts the accepted WebSockets, verified or not, that have not
	// closed.
	open int
}

// accept counts one more accepted WebSocket. It returns false, and counts
// nothing, when maxAccepted WebSockets are open.
func (p *authPool) accept() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.open >= maxAccepted {
		return false
	}
	p.open++
	return true
}

// release counts one accepted WebSocket as closed.
func (p *authPool) release() {
	p.mu.Lock()
	p.open--
	p.mu.Unlock()
}

// push adds a verified stream. When more than maxAuthStreams WebSockets are
// open, it closes the oldest waiting stream, unless c is the only one
// waiting. It returns true if it closed one.
func (p *authPool) push(c *wsConn) bool {
	p.mu.Lock()
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
