package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// Callout protocol names.
const (
	CalloutPath   = "/tunnel/auth"
	CalloutDomain = "sallyport/authpipe/v1"
	NonceBytes    = 32
)

// CalloutOpts changes how a fake callout stream answers the challenge.
type CalloutOpts struct {
	// Key signs the challenge. Nil means the cluster's callout key.
	Key ed25519.PrivateKey
	// Host is the host signed into the challenge. Empty means LoginHost,
	// the test hub's CALLOUT_HOST.
	Host string
}

// DialCalloutWS opens a WebSocket to /tunnel/auth without answering the
// challenge. The response is set when the upgrade fails.
func (h *Hub) DialCalloutWS(ctx context.Context) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{NetDialContext: h.DialContext, TLSClientConfig: EdgeTLS(), HandshakeTimeout: 20 * time.Second}
	return d.DialContext(ctx, "wss://"+LoginHost+CalloutPath, nil)
}

// DialCallout opens a stream to /tunnel/auth and answers the hub's
// challenge the way auth's callout does. It does not wait to learn
// whether the hub accepted the answer.
func (h *Hub) DialCallout(ctx context.Context, p *PKI, opts CalloutOpts) (*websocket.Conn, error) {
	ws, resp, err := h.DialCalloutWS(ctx)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("callout websocket: %w (status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("callout websocket: %w", err)
	}
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, hubNonce, err := ws.ReadMessage()
	ws.SetReadDeadline(time.Time{})
	if err != nil {
		ws.Close()
		return nil, fmt.Errorf("callout nonce: %w", err)
	}
	if len(hubNonce) != NonceBytes {
		ws.Close()
		return nil, fmt.Errorf("callout nonce is %d bytes, want %d", len(hubNonce), NonceBytes)
	}
	key := opts.Key
	if key == nil {
		key = p.Callout
	}
	host := opts.Host
	if host == "" {
		host = LoginHost
	}
	authNonce := make([]byte, NonceBytes)
	rand.Read(authNonce)
	msg := append(append(append([]byte(CalloutDomain), host...), hubNonce...), authNonce...)
	if err := ws.WriteMessage(websocket.BinaryMessage, append(authNonce, ed25519.Sign(key, msg)...)); err != nil {
		ws.Close()
		return nil, fmt.Errorf("callout reply: %w", err)
	}
	return ws, nil
}

// WaitClosed reads from ws until it closes or d passes. It returns the
// close error, or nil if ws was still open after d. Messages that arrive
// are returned in msgs.
func WaitClosed(ws *websocket.Conn, d time.Duration) (msgs [][]byte, closeErr error) {
	ws.SetReadDeadline(time.Now().Add(d))
	defer ws.SetReadDeadline(time.Time{})
	for {
		_, m, err := ws.ReadMessage()
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				return msgs, nil
			}
			return msgs, err
		}
		msgs = append(msgs, m)
	}
}
