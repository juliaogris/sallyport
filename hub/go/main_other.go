//go:build !(js && wasm)

package main

// The hub runs only as js/wasm in a Durable Object. This file lets the
// portable parts build and test natively.

type bodyStream struct{}

// wsConn stands in for the WebSocket connection. It records a close and
// nothing else, so that authPool can be tested natively.
type wsConn struct {
	closed bool
}

func (c *wsConn) isClosed() bool { return c.closed }

func (c *wsConn) CloseWith(code int, reason string) error {
	c.closed = true
	return nil
}

func main() {}
