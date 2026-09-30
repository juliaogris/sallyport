package conformance

import (
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSConn is a net.Conn over a WebSocket with binary messages, as the
// agent and auth's callout use it.
type WSConn struct {
	ws  *websocket.Conn
	mu  sync.Mutex
	buf []byte
}

// NewWSConn returns a net.Conn over ws.
func NewWSConn(ws *websocket.Conn) *WSConn { return &WSConn{ws: ws} }

func (c *WSConn) Read(b []byte) (int, error) {
	for len(c.buf) == 0 {
		_, m, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		c.buf = m
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *WSConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSConn) Close() error                       { return c.ws.Close() }
func (c *WSConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error      { return c.ws.NetConn().SetDeadline(t) }
func (c *WSConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
