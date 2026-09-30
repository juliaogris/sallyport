package conformance

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// TestCalloutChallenge checks that the hub keeps a callout stream that
// answers the challenge and closes one that does not.
func TestCalloutChallenge(t *testing.T) {
	logOnFailure(t, shared)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cases := []struct {
		name string
		opts CalloutOpts
		keep bool
	}{
		{name: "valid", keep: true},
		{name: "other key", opts: CalloutOpts{Key: otherKey}},
		{name: "other host", opts: CalloutOpts{Host: "other.test"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws, err := shared.DialCallout(t.Context(), pki, c.opts)
			require.NoError(t, err)
			defer ws.Close()
			_, closeErr := WaitClosed(ws, 3*time.Second)
			if c.keep {
				require.NoError(t, closeErr, "hub closed a verified stream")
				return
			}
			require.Error(t, closeErr, "hub kept a stream that failed the challenge")
			require.True(t, websocket.IsCloseError(closeErr, websocket.ClosePolicyViolation), "close: %v", closeErr)
		})
	}
}

// TestCalloutPassthrough checks that an Instance agent's dial to
// @remote-auth-server is copied both ways to a verified callout stream.
func TestCalloutPassthrough(t *testing.T) {
	h := freshHub(t)
	ws, err := h.DialCallout(t.Context(), pki, CalloutOpts{})
	require.NoError(t, err)
	defer ws.Close()
	// Give the hub time to put the stream in its pool.
	time.Sleep(time.Second)

	id, err := pki.AgentIdentity("Instance")
	require.NoError(t, err)
	a, err := h.DialAgent(t.Context(), pki, id)
	require.NoError(t, err)
	defer a.Close()
	ch, ok, err := a.OpenTransport(AddrRemoteAuth)
	require.NoError(t, err)
	require.True(t, ok, "dial to %s refused", AddrRemoteAuth)
	defer ch.Close()

	_, err = ch.Write([]byte("hello auth"))
	require.NoError(t, err)
	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got []byte
	for len(got) < len("hello auth") {
		_, m, err := ws.ReadMessage()
		require.NoError(t, err)
		got = append(got, m...)
	}
	require.Equal(t, "hello auth", string(got))

	require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, []byte("hello agent")))
	buf := make([]byte, len("hello agent"))
	_, err = io.ReadFull(ch, buf)
	require.NoError(t, err)
	require.Equal(t, "hello agent", string(buf))

	// Closing the agent's channel closes the callout stream.
	ch.Close()
	_, closeErr := WaitClosed(ws, 10*time.Second)
	require.Error(t, closeErr, "callout stream still open 10s after the agent closed its channel")
}

// TestCalloutPassthroughNoStream checks that a dial to @remote-auth-server
// is refused, not left hanging, when no callout stream is open.
func TestCalloutPassthroughNoStream(t *testing.T) {
	h := freshHub(t)
	id, err := pki.AgentIdentity("Instance")
	require.NoError(t, err)
	a, err := h.DialAgent(t.Context(), pki, id)
	require.NoError(t, err)
	defer a.Close()

	start := time.Now()
	ch, ok, err := a.OpenTransport(AddrRemoteAuth)
	if ch != nil {
		defer ch.Close()
	}
	if err == nil {
		require.False(t, ok, "dial to %s accepted with no callout stream", AddrRemoteAuth)
	}
	require.Less(t, time.Since(start), 10*time.Second)
}

// TestCalloutStreamLimit checks that with 8 streams waiting, a newly
// verified stream closes the oldest waiting one. Auth opens 8 streams, so
// a stream whose auth went away without closing it must not hold its
// place forever.
func TestCalloutStreamLimit(t *testing.T) {
	h := freshHub(t)
	var streams []*websocket.Conn
	defer func() {
		for _, ws := range streams {
			ws.Close()
		}
	}()
	for range 8 {
		ws, err := h.DialCallout(t.Context(), pki, CalloutOpts{})
		require.NoError(t, err)
		streams = append(streams, ws)
	}
	time.Sleep(time.Second)

	ninth, err := h.DialCallout(t.Context(), pki, CalloutOpts{})
	require.NoError(t, err, "ninth stream refused")
	streams = append(streams, ninth)

	_, closeErr := WaitClosed(streams[0], 5*time.Second)
	require.Error(t, closeErr, "oldest stream still open after a ninth was verified")
	for i := 1; i < len(streams); i++ {
		_, closeErr := WaitClosed(streams[i], 200*time.Millisecond)
		require.NoError(t, closeErr, "stream %d closed", i)
	}
}
