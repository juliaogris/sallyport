package conformance

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// TestLazyRefuse checks the "refuse <id>" message: the hub offers it on
// the control socket upgrade, completes a refused dial at once, and uses
// up the refused id.
func TestLazyRefuse(t *testing.T) {
	t.Run("offered on the upgrade", func(t *testing.T) {
		h := lazyHub(t)
		ws, resp, err := h.DialControlResp(t.Context(), pki, nil, nil)
		require.NoError(t, err)
		ws.Close()
		require.Equal(t, "refuse", resp.Header.Get(ControlHeader))
	})

	s := newLazyStack(t)

	t.Run("app request", func(t *testing.T) {
		cookies := s.appCookies(t, "bench")
		s.auth.SetLazyDial(LazyDialRefuse)
		req, _ := http.NewRequest("GET", "https://"+appHost("bench")+"/t/static", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		start := time.Now()
		resp, err := s.hub.Do(req)
		s.auth.SetLazyDial(LazyDialServe)
		require.NoError(t, err)
		body := readBody(t, resp)
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		require.Equal(t, "app service busy", string(body))
		require.Less(t, time.Since(start), 5*time.Second, "the refused dial waited for its deadline")
		require.NotEmpty(t, s.auth.Refused())

		resp = s.get(t, appHost("bench"), "/t/static", cookies...)
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "the next request")
	})

	t.Run("refused id is used up", func(t *testing.T) {
		refused := s.auth.Refused()
		require.NotEmpty(t, refused)
		_, resp, err := s.hub.DialLazy(t.Context(), "stream", http.Header{StreamIDHeader: {refused[0]}})
		require.Error(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("passkey route", func(t *testing.T) {
		session := s.login(t)
		// The hub keeps its auth connection for 5 s after the last call.
		time.Sleep(6 * time.Second)
		s.auth.SetLazyAuthDial(LazyDialRefuse)
		resp := s.get(t, LoginHost, "/webapi/passkeys", session)
		s.auth.SetLazyAuthDial(LazyDialServe)
		body := readBody(t, resp)
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "body %q", body)
		require.Equal(t, "auth unavailable", strings.TrimSpace(string(body)))
	})
}

// TestLazyControlText checks that a refuse for an id that is not pending
// leaves the control socket open, and that any other text closes it.
func TestLazyControlText(t *testing.T) {
	h := lazyHub(t)
	ws, err := h.DialControl(t.Context(), pki, nil)
	require.NoError(t, err)
	t.Cleanup(func() { ws.Close() })
	require.True(t, h.WaitLog(controlVerified, 1, 10*time.Second))

	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("refuse "+newID(t))))
	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("ping")))
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := ws.ReadMessage()
	require.NoError(t, err, "the control socket closed after a refuse for an unknown id")
	require.Equal(t, "pong", string(msg))

	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("hello")))
	_, closeErr := WaitClosed(ws, 5*time.Second)
	require.Error(t, closeErr, "the control socket stayed open after unknown text")
}

// TestLazyBadUploadAck checks that the hub closes a stream with 1008 when
// the callout sends an ack that is not a number, goes backwards, or is
// above the bytes the hub sent.
func TestLazyBadUploadAck(t *testing.T) {
	s := newLazyStack(t)
	for _, c := range []struct {
		name string
		dial LazyDial
	}{
		{"not a number", LazyDialAckText},
		{"backwards", LazyDialAckBackwards},
		{"above the bytes sent", LazyDialAckAbove},
	} {
		t.Run(c.name, func(t *testing.T) {
			cookies := s.appCookies(t, "bench")
			before := len(s.auth.AckCloses())
			s.auth.SetLazyDial(c.dial)
			status, _ := s.timedGet(t, "/t/static", cookies, 20*time.Second)
			s.auth.SetLazyDial(LazyDialServe)
			require.GreaterOrEqual(t, status, 500)
			require.Eventually(t, func() bool { return len(s.auth.AckCloses()) > before }, 15*time.Second, 100*time.Millisecond)
			require.Equal(t, websocket.ClosePolicyViolation, s.auth.AckCloses()[before])
		})
	}
}

// TestLazyControlEviction checks that at the cap of 4 pending control
// sockets the client with the most pending sockets loses its oldest one,
// closed with 1013. Clients are told apart by CF-Connecting-IP, and IPv6
// addresses in one /64 are one client.
func TestLazyControlEviction(t *testing.T) {
	h := lazyHub(t)
	dial := func(ip string) *websocket.Conn {
		ws, _, err := h.DialLazy(t.Context(), "control", http.Header{"Cf-Connecting-Ip": {ip}})
		require.NoError(t, err)
		t.Cleanup(func() { ws.Close() })
		return ws
	}
	// B has the oldest socket. A has three in one /64. A fifth from B
	// must close A's oldest, not B's.
	b0 := dial("192.0.2.7")
	a1 := dial("2001:db8:1:2::1")
	a2 := dial("2001:db8:1:2::2")
	a3 := dial("2001:db8:1:2:ffff::3")
	b4 := dial("192.0.2.7")

	_, err := WaitClosed(a1, 5*time.Second)
	require.Error(t, err, "A's oldest pending socket stayed open")
	var ce *websocket.CloseError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, websocket.CloseTryAgainLater, ce.Code)
	for name, ws := range map[string]*websocket.Conn{"b0": b0, "a2": a2, "a3": a3, "b4": b4} {
		_, err := WaitClosed(ws, 200*time.Millisecond)
		require.NoError(t, err, "%s closed", name)
	}
}

// TestLazyQuietResponse checks an app that sends nothing for 35 s before
// it answers. The lazy hub closes a stream after 30 s without bytes, so
// the browser gets 502 after about 30 s.
func TestLazyQuietResponse(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	status, took := s.timedGet(t, "/t/quiet?secs=35", cookies, 60*time.Second)
	t.Logf("%d after %v", status, took.Round(100*time.Millisecond))
	require.Equal(t, http.StatusBadGateway, status)
	require.Greater(t, took, 25*time.Second)
	require.Less(t, took, 40*time.Second)
}
