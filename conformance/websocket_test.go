package conformance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

// TestAppWebSocket checks a WebSocket from a logged-in browser to an app,
// through the agent tunnel.
func TestAppWebSocket(t *testing.T) {
	s := newStack(t)
	testAppWebSocket(t, s, s.appCookies(t, "bench"))
}

// TestLazyAppWebSocket checks a WebSocket from a logged-in browser to an
// app, through a stream from auth's callout.
func TestLazyAppWebSocket(t *testing.T) {
	s := newLazyStack(t)
	testAppWebSocket(t, s, s.appCookies(t, "bench"))
}

func testAppWebSocket(t *testing.T, s *stack, cookies []*http.Cookie) {
	host := appHost("bench")

	t.Run("handshake", func(t *testing.T) {
		extra := append([]*http.Cookie{{Name: "app", Value: "1"}}, cookies...)
		ws, resp := s.dialWS(t, host, "/t/ws?hello=1", origin(host), extra...)
		require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
		require.Equal(t, "chat", ws.Subprotocol())
		typ, msg, err := ws.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, websocket.TextMessage, typ)
		var e testapp.Echo
		require.NoError(t, json.Unmarshal(msg, &e))
		require.Equal(t, Alice, e.Client)
		require.Equal(t, host, e.Host)
		require.Equal(t, "/t/ws?hello=1", e.URI)
		require.Equal(t, []string{"app=1"}, e.Header["Cookie"])
		require.Equal(t, []string{"chat"}, e.Header["Sec-Websocket-Protocol"])
	})

	t.Run("echo", func(t *testing.T) {
		ws, _ := s.dialWS(t, host, "/t/ws", origin(host), cookies...)
		for i := range 200 {
			typ := websocket.TextMessage
			if i%2 == 1 {
				typ = websocket.BinaryMessage
			}
			msg := []byte("message " + itoa(i))
			require.NoError(t, ws.WriteMessage(typ, msg))
			gotTyp, got, err := ws.ReadMessage()
			require.NoError(t, err)
			require.Equal(t, typ, gotTyp)
			require.Equal(t, msg, got)
		}
	})

	t.Run("pipelined", func(t *testing.T) {
		ws, _ := s.dialWS(t, host, "/t/ws", origin(host), cookies...)
		const n = 1000
		go func() {
			for i := range n {
				ws.WriteMessage(websocket.TextMessage, []byte(itoa(i)))
			}
		}()
		for i := range n {
			_, got, err := ws.ReadMessage()
			require.NoError(t, err)
			require.Equal(t, itoa(i), string(got))
		}
	})

	t.Run("large messages", func(t *testing.T) {
		ws, _ := s.dialWS(t, host, "/t/ws", origin(host), cookies...)
		const n = 1000 << 10
		big := testapp.Pattern(n)
		require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, big))
		typ, got, err := ws.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, websocket.BinaryMessage, typ)
		require.Equal(t, big, got)

		require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("big "+itoa(n))))
		typ, got, err = ws.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, websocket.BinaryMessage, typ)
		require.Equal(t, big, got)

		text := strings.Repeat("ü", n/2)
		require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte(text)))
		typ, got, err = ws.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, websocket.TextMessage, typ)
		require.Equal(t, text, string(got))
	})

	t.Run("close from the browser", func(t *testing.T) {
		id := newID(t)
		ws, _ := s.dialWS(t, host, "/t/ws?id="+id, origin(host), cookies...)
		require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("hi")))
		_, _, err := ws.ReadMessage()
		require.NoError(t, err)
		require.NoError(t, ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "bye"), time.Now().Add(5*time.Second)))
		resp := s.get(t, host, "/t/wsclosed?id="+id, cookies...)
		require.Equal(t, "4001\n", string(readBody(t, resp)))
	})

	t.Run("close from the app", func(t *testing.T) {
		ws, _ := s.dialWS(t, host, "/t/ws", origin(host), cookies...)
		require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("close 4002 done")))
		ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _, err := ws.ReadMessage()
		var ce *websocket.CloseError
		require.True(t, errors.As(err, &ce), "read: %v", err)
		require.Equal(t, 4002, ce.Code)
		require.Equal(t, "done", ce.Text)
	})

	t.Run("quiet for 40 s", func(t *testing.T) {
		ws, _ := s.dialWS(t, host, "/t/ws", origin(host), cookies...)
		time.Sleep(40 * time.Second)
		require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("still there")))
		ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, got, err := ws.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, "still there", string(got))
	})

	t.Run("no cookies", func(t *testing.T) {
		resp := s.failWS(t, host, "/t/ws", origin(host))
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	})

	t.Run("from another site", func(t *testing.T) {
		for _, o := range []string{origin(appHost("cam")), origin(LoginHost), "https://other.test"} {
			resp := s.failWS(t, host, "/t/ws", o, cookies...)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "origin %s", o)
		}
	})
}

// dialWS opens a WebSocket to path on host with the subprotocol "chat",
// and closes it when the test ends.
func (s *stack) dialWS(t *testing.T, host, path, origin string, cookies ...*http.Cookie) (*websocket.Conn, *http.Response) {
	t.Helper()
	ws, resp, err := s.wsDialer().DialContext(t.Context(), "wss://"+host+path, wsHeader(origin, cookies))
	if resp != nil && err != nil {
		t.Fatalf("dial %s: %v, status %d", path, err, resp.StatusCode)
	}
	require.NoError(t, err)
	t.Cleanup(func() { ws.Close() })
	ws.SetReadLimit(64 << 20)
	return ws, resp
}

// failWS tries to open a WebSocket to path on host, and returns the
// response of the refused handshake.
func (s *stack) failWS(t *testing.T, host, path, origin string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	ws, resp, err := s.wsDialer().DialContext(t.Context(), "wss://"+host+path, wsHeader(origin, cookies))
	if err == nil {
		ws.Close()
		t.Fatalf("dial %s: the hub accepted the WebSocket", path)
	}
	require.NotNil(t, resp, "dial %s: %v", path, err)
	return resp
}

func (s *stack) wsDialer() *websocket.Dialer {
	return &websocket.Dialer{
		NetDialContext:   s.hub.DialContext,
		TLSClientConfig:  EdgeTLS(),
		Subprotocols:     []string{"chat"},
		HandshakeTimeout: 30 * time.Second,
	}
}

func wsHeader(origin string, cookies []*http.Cookie) http.Header {
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	var parts []string
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	if len(parts) > 0 {
		h.Set("Cookie", strings.Join(parts, "; "))
	}
	return h
}

// TestAppDrip checks that a long-held streamed response, like a SockJS
// xhr_streaming one, reaches the browser line by line as the app sends it.
func TestAppDrip(t *testing.T) {
	s := newStack(t)
	testAppDrip(t, s, s.appCookies(t, "bench"))
}

// TestLazyAppDrip is TestAppDrip through a stream from auth's callout.
func TestLazyAppDrip(t *testing.T) {
	s := newLazyStack(t)
	testAppDrip(t, s, s.appCookies(t, "bench"))
}

func testAppDrip(t *testing.T, s *stack, cookies []*http.Cookie) {
	const n, every = 8, 500 * time.Millisecond
	start := time.Now()
	resp := s.get(t, appHost("bench"), "/t/drip?n="+itoa(n)+"&ms="+itoa(int(every/time.Millisecond)), cookies...)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	r := bufio.NewReader(resp.Body)
	prelude, err := r.ReadBytes('\n')
	require.NoError(t, err)
	require.Equal(t, append(bytes.Repeat([]byte("h"), 2048), '\n'), prelude)
	require.Less(t, time.Since(start), 2*time.Second, "the prelude waited for more of the body")
	for i := range n {
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "a[\""+itoa(i)+"\"]\n", line)
		// Line i is sent (i+1)*every after the prelude. One that arrives
		// much later was held back with the lines after it.
		require.Less(t, time.Since(start), time.Duration(i+1)*every+2*time.Second, "line %d came late", i)
	}
}
