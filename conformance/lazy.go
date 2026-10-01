package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// StreamIDHeader carries the stream id on a lazy hub's stream request.
const StreamIDHeader = "Sallyport-Stream-Id"

// LazyVars returns the vars of a hub in lazy mode.
func LazyVars() map[string]string {
	v := BaseVars()
	v["HUB_MODE"] = "lazy"
	return v
}

// AppServer serves the test app on the streams it is given, as the app
// service does: TLS with a certificate for the cluster's app SNI, a client
// certificate from the cluster TLS CA required, then HTTP/1.1.
type AppServer struct {
	ln *connListener
}

// NewAppServer starts an app server for handler.
func NewAppServer(p *PKI, handler http.Handler) (*AppServer, error) {
	sni := hex.EncodeToString([]byte(p.Cluster)) + "." + authSNI
	cert, err := p.TLSLeaf(sni, sni)
	if err != nil {
		return nil, err
	}
	ln := newConnListener()
	srv := &http.Server{Handler: handler}
	go srv.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.TLSCAPool,
	}))
	return &AppServer{ln: ln}, nil
}

// Close stops the app server.
func (s *AppServer) Close() { s.ln.Close() }

// DialLazy opens a WebSocket to /tunnel/auth with the given mode and
// request headers, without answering any challenge.
func (h *Hub) DialLazy(ctx context.Context, mode string, header http.Header) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{NetDialContext: h.DialContext, TLSClientConfig: EdgeTLS(), HandshakeTimeout: 20 * time.Second}
	return d.DialContext(ctx, "wss://"+LoginHost+CalloutPath+"?mode="+mode, header)
}

// DialControl opens a control socket and answers the hub's challenge with
// key, or the cluster's callout key if key is nil.
func (h *Hub) DialControl(ctx context.Context, p *PKI, key ed25519.PrivateKey) (*websocket.Conn, error) {
	ws, resp, err := h.DialLazy(ctx, "control", nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("control websocket: %w (status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("control websocket: %w", err)
	}
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, hubNonce, err := ws.ReadMessage()
	ws.SetReadDeadline(time.Time{})
	if err != nil || len(hubNonce) != NonceBytes {
		ws.Close()
		return nil, fmt.Errorf("control nonce: %v, %d bytes", err, len(hubNonce))
	}
	if key == nil {
		key = p.Callout
	}
	authNonce := make([]byte, NonceBytes)
	rand.Read(authNonce)
	msg := append(append(append([]byte(CalloutDomain), LoginHost...), hubNonce...), authNonce...)
	if err := ws.WriteMessage(websocket.BinaryMessage, append(authNonce, ed25519.Sign(key, msg)...)); err != nil {
		ws.Close()
		return nil, fmt.Errorf("control reply: %w", err)
	}
	return ws, nil
}

// RunLazy keeps a control socket open to h, as auth's callout does with
// callout_mode: on_demand, and opens a stream for each dial the hub sends.
// Auth streams go to a's listener, and app streams to app. It redials the
// control socket until ctx ends.
func (a *FakeAuth) RunLazy(ctx context.Context, h *Hub, app *AppServer) {
	go func() {
		for ctx.Err() == nil {
			if err := a.serveControl(ctx, h, app); err != nil && ctx.Err() == nil {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()
}

func (a *FakeAuth) serveControl(ctx context.Context, h *Hub, app *AppServer) error {
	ws, err := h.DialControl(ctx, a.pki, nil)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.sockets[ws] = true
	a.mu.Unlock()
	defer a.drop(ws)
	stop := context.AfterFunc(ctx, func() { ws.Close() })
	defer stop()
	for {
		typ, msg, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if typ != websocket.TextMessage {
			return fmt.Errorf("control message is not text")
		}
		parts := strings.Split(string(msg), " ")
		if len(parts) != 3 || parts[0] != "dial" {
			continue
		}
		go a.serveLazyStream(ctx, h, app, parts[1], parts[2])
	}
}

func (a *FakeAuth) serveLazyStream(ctx context.Context, h *Hub, app *AppServer, kind, id string) {
	ws, _, err := h.DialLazy(ctx, "stream", http.Header{StreamIDHeader: {id}})
	if err != nil {
		return
	}
	conn := NewWSConn(ws)
	switch kind {
	case "auth":
		if !a.ln.put(conn) {
			ws.Close()
		}
	case "app":
		if app == nil || !app.ln.put(conn) {
			ws.Close()
		}
	default:
		ws.Close()
	}
}
