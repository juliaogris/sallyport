package conformance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

// newLazyStack starts a hub in lazy mode, keeps a control socket open to
// it, and serves the test app on the app streams it asks for.
func newLazyStack(t *testing.T) *stack {
	t.Helper()
	h := lazyHub(t)
	auth, err := NewFakeAuth(pki)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	app, err := NewAppServer(pki, testapp.Handler(""))
	require.NoError(t, err)
	t.Cleanup(app.Close)
	auth.RunLazy(t.Context(), h, app)
	// The hub sends dials only once the control socket is verified.
	require.True(t, h.WaitLog(controlVerified, 1, 20*time.Second), "no control socket verified")
	t.Cleanup(func() {
		require.Empty(t, auth.BadDialIDs(), "dial ids that are not 43 characters of base64url")
	})
	return &stack{hub: h, auth: auth}
}

// lazyHub starts a hub of its own in lazy mode.
func lazyHub(t *testing.T) *Hub {
	t.Helper()
	dir := filepath.Join(tmp, t.Name())
	require.NoError(t, os.MkdirAll(dir, 0o700))
	h, err := StartHub(t.Context(), hubDir, dir, LazyVars(), pki.Secrets())
	require.NoError(t, err)
	t.Cleanup(h.Stop)
	logOnFailure(t, h)
	return h
}

// controlVerified is the log line both hubs write when a control socket
// passes the challenge.
const controlVerified = "lazy: control socket verified"

func newID(t *testing.T) string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestLazyAppProxy(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	host := appHost("bench")

	t.Run("static", func(t *testing.T) {
		resp := s.get(t, host, "/t/static", cookies...)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, testapp.StaticBody, body)
	})

	t.Run("user certificate", func(t *testing.T) {
		e := s.echo(t, cookies, nil)
		require.Equal(t, Alice, e.Client)
		require.Equal(t, host, e.Host)
	})

	// A body far larger than the window needs the hub's acks to arrive.
	t.Run("32 MiB body", func(t *testing.T) {
		resp := s.get(t, host, "/t/bytes?n=33554432&len=1", cookies...)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Len(t, body, 32<<20)
	})
}

func TestLazyAutoResponsePong(t *testing.T) {
	h := lazyHub(t)
	ws, err := h.DialControl(t.Context(), pki, nil)
	require.NoError(t, err)
	t.Cleanup(func() { ws.Close() })
	require.True(t, h.WaitLog(controlVerified, 1, 10*time.Second))
	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("ping")))
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, msg, err := ws.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, typ)
	require.Equal(t, "pong", string(msg))
}

func TestLazyStreamUnknownID(t *testing.T) {
	h := lazyHub(t)
	_, resp, err := h.DialLazy(t.Context(), "stream", http.Header{StreamIDHeader: {newID(t)}})
	require.Error(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestLazyBadSignatureClosesControl(t *testing.T) {
	h := lazyHub(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ws, err := h.DialControl(t.Context(), pki, other)
	require.NoError(t, err)
	t.Cleanup(func() { ws.Close() })
	_, closeErr := WaitClosed(ws, 5*time.Second)
	require.Error(t, closeErr, "a control socket with a bad signature stayed open")
}

func TestLazyControlReplaced(t *testing.T) {
	h := lazyHub(t)
	first, err := h.DialControl(t.Context(), pki, nil)
	require.NoError(t, err)
	t.Cleanup(func() { first.Close() })
	require.True(t, h.WaitLog(controlVerified, 1, 10*time.Second))
	second, err := h.DialControl(t.Context(), pki, nil)
	require.NoError(t, err)
	t.Cleanup(func() { second.Close() })
	_, closeErr := WaitClosed(first, 5*time.Second)
	require.Error(t, closeErr, "the older control socket stayed open")
}

func TestLazyPendingControlClosed(t *testing.T) {
	h := lazyHub(t)
	pending, _, err := h.DialLazy(t.Context(), "control", nil)
	require.NoError(t, err)
	t.Cleanup(func() { pending.Close() })
	// The hub closes stale pending sockets on its next event.
	time.Sleep(11 * time.Second)
	ws, err := h.DialControl(t.Context(), pki, nil)
	require.NoError(t, err)
	t.Cleanup(func() { ws.Close() })
	msgs, closeErr := WaitClosed(pending, 5*time.Second)
	require.Error(t, closeErr, "a control socket that never answered stayed open, got %d messages", len(msgs))
}

func TestLazyNoAgentTunnel(t *testing.T) {
	h := lazyHub(t)
	id, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	_, err = h.DialAgent(t.Context(), pki, id)
	require.Error(t, err, "the lazy hub accepted an agent tunnel")
}
