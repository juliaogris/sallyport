package conformance

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// TestTunnelAuthDeadline checks that a tunnel that does not authenticate
// is closed after about 30 seconds.
func TestTunnelAuthDeadline(t *testing.T) {
	t.Parallel()
	logOnFailure(t, shared)
	tc, err := shared.DialTunnelTLS(t.Context(), pki)
	require.NoError(t, err)
	defer tc.Close()
	start := time.Now()
	tc.SetReadDeadline(time.Now().Add(45 * time.Second))
	buf := make([]byte, 1024)
	for {
		if _, err = tc.Read(buf); err != nil {
			break
		}
	}
	took := time.Since(start)
	require.Greater(t, took, 25*time.Second, "closed after %v: %v", took, err)
	require.Less(t, took, 40*time.Second, "not closed after %v", took)
}

// TestTunnelConnectionLimit checks that with 8 tunnels that have not
// authenticated, a 9th closes the oldest and stays open itself. Clients
// that never authenticate must not keep a redialing agent out. Every tunnel
// here has the same client address, so the oldest tunnel is the one that
// goes.
func TestTunnelConnectionLimit(t *testing.T) {
	h := freshHub(t)
	var open []*websocket.Conn
	defer func() {
		for _, ws := range open {
			ws.Close()
		}
	}()
	for i := range 9 {
		ws, _, err := h.DialTunnelWS(t.Context(), TunnelSubprotocol)
		require.NoError(t, err, "tunnel %d refused", i+1)
		open = append(open, ws)
	}

	_, closeErr := WaitClosed(open[0], 5*time.Second)
	require.Error(t, closeErr, "oldest tunnel still open after a 9th")
	for i := 1; i < len(open); i++ {
		_, closeErr := WaitClosed(open[i], 100*time.Millisecond)
		require.NoError(t, closeErr, "tunnel %d closed", i+1)
	}
}

// TestTunnelAuthenticatedLimit checks that with 16 authenticated tunnels
// the hub refuses a 17th tunnel with 503.
func TestTunnelAuthenticatedLimit(t *testing.T) {
	h := freshHub(t)
	id, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	for i := range 16 {
		a, err := h.DialAgent(t.Context(), pki, id)
		require.NoError(t, err, "agent %d refused", i+1)
		t.Cleanup(func() { a.Close() })
	}

	ws, resp, err := h.DialTunnelWS(t.Context(), TunnelSubprotocol)
	if ws != nil {
		ws.Close()
	}
	require.Error(t, err, "17th tunnel accepted")
	require.NotNil(t, resp, "no response for the 17th tunnel")
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "too many connections", string(body))
}

// TestDiscoveryInterval checks that the hub announces itself again about
// 30 seconds after the first announcement.
func TestDiscoveryInterval(t *testing.T) {
	t.Parallel()
	logOnFailure(t, shared)
	id, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	a, err := shared.DialAgent(t.Context(), pki, id)
	require.NoError(t, err)
	defer a.Close()
	_, ok, err := a.Heartbeat()
	require.NoError(t, err)
	require.True(t, ok)
	select {
	case <-a.Discovery:
	case <-time.After(10 * time.Second):
		t.Fatal("no first discovery")
	}
	start := time.Now()
	select {
	case <-a.Discovery:
		took := time.Since(start)
		require.Greater(t, took, 25*time.Second)
		require.Less(t, took, 40*time.Second)
	case <-time.After(45 * time.Second):
		t.Fatal("no second discovery within 45s")
	}
}

// TestCalloutRecovery checks that app requests still work after every
// callout stream closes, once auth has opened new ones.
func TestCalloutRecovery(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	resp := s.get(t, appHost("bench"), "/t/static", cookies...)
	readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	s.auth.DropStreams()
	time.Sleep(2 * time.Second)
	resp = s.get(t, appHost("bench"), "/t/static", cookies...)
	body := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "first request after the drop: %s", body)
}

// TestLoginRateLimited checks that auth's rate limit reaches the browser
// as 429.
func TestLoginRateLimited(t *testing.T) {
	s := newStack(t)
	s.auth.SetRateLimited(true)
	for _, path := range []string{"/webapi/login/begin", "/webapi/invite/" + BobInvite + "/begin"} {
		t.Run(path, func(t *testing.T) {
			resp := s.post(t, LoginHost, path, origin(LoginHost), "")
			readBody(t, resp)
			require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		})
	}
	s.auth.SetRateLimited(false)
	resp := s.post(t, LoginHost, "/webapi/login/begin", origin(LoginHost), "")
	readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestApp101 checks that an app's 101 to a request without Upgrade is
// answered with an error within 10 seconds and that the hub keeps serving.
func TestApp101(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	req, _ := http.NewRequest("GET", "https://"+appHost("bench")+"/t/status/101", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	cl := s.hub.Client()
	cl.Timeout = 10 * time.Second
	resp, err := cl.Do(req)
	require.NoError(t, err, "no answer to the 101")
	readBody(t, resp)
	require.GreaterOrEqual(t, resp.StatusCode, 500)
	resp = s.get(t, appHost("bench"), "/t/static", cookies...)
	readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

var scriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// TestHandoffStartPath runs the handoff page's script in node and checks
// where it sends the browser after the handoff, for each start path in the
// URL fragment.
func TestHandoffStartPath(t *testing.T) {
	logOnFailure(t, shared)
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found")
	}
	resp, err := shared.Get(appHost("bench"), "/x-teleport-auth?state=x")
	require.NoError(t, err)
	page := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	m := scriptRE.FindSubmatch(page)
	require.NotNil(t, m, "no script in the handoff page")

	cases := map[string]string{
		"/":                  "/",
		"/stream":            "/stream",
		"/a/b?c=d":           "/a/b?c=d",
		"/a/b?x=/../":        "/a/b?x=/../",
		"//other.test/":      "/",
		`/\other.test/`:      "/",
		`\\other.test`:       "/",
		"/\t/other.test/":    "/",
		"/\n/other.test/":    "/",
		"/.//other.test/":    "/",
		"/%2e%2E/other.test": "/",
		"/a/../b":            "/",
		"https://other.test": "/",
		"":                   "/",
	}
	for start, want := range cases {
		t.Run(start, func(t *testing.T) {
			hash := "#sid.bearer." + base64.RawURLEncoding.EncodeToString([]byte(start))
			got := runHandoffScript(t, string(m[1]), hash)
			require.Equal(t, want, got)
		})
	}
	t.Run("not base64", func(t *testing.T) {
		require.Equal(t, "/", runHandoffScript(t, string(m[1]), "#sid.bearer.%%%"))
	})
}

// runHandoffScript runs script with a fake browser whose URL fragment is
// hash and whose handoff POST succeeds. It returns the path the script
// navigates to.
func runHandoffScript(t *testing.T, script, hash string) string {
	t.Helper()
	harness := `
const vm = require('vm');
let replaced = null;
const location = {
  hash: process.argv[2], search: '?state=x', pathname: '/x-teleport-auth',
  replace: p => { replaced = p; }, set href(p) { replaced = p; },
};
const ctx = {
  location, atob, URLSearchParams,
  history: { replaceState() {} },
  document: { getElementById: () => ({}) },
  fetch: () => Promise.resolve({ ok: true, text: () => Promise.resolve('') }),
};
vm.runInNewContext(process.argv[1], ctx);
setTimeout(() => console.log(JSON.stringify(replaced)), 50);
`
	out, err := exec.CommandContext(t.Context(), "node", "-e", harness, script, hash).CombinedOutput()
	require.NoError(t, err, "node: %s", out)
	var got string
	require.NoError(t, json.Unmarshal(out, &got), "node printed %s", out)
	return got
}
