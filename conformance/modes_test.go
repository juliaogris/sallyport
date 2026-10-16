package conformance

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stackFor returns a new stack in mode, "tunnel" or "lazy".
func stackFor(t *testing.T, mode string) *stack {
	t.Helper()
	return stackForVars(t, mode, BaseVars())
}

// stackForVars returns a new stack in mode whose hub runs with vars.
func stackForVars(t *testing.T, mode string, vars map[string]string) *stack {
	t.Helper()
	if mode == "lazy" {
		vars["HUB_MODE"] = "lazy"
		return newLazyStackVars(t, vars)
	}
	return newStackVars(t, vars)
}

var modes = []string{"tunnel", "lazy"}

// TestAppHead checks that a HEAD the app answers with a Content-Length and
// no body reaches the browser as a clean 200 with that Content-Length.
func TestAppHead(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			s := stackFor(t, mode)
			cookies := s.appCookies(t, "bench")
			req, _ := http.NewRequest("HEAD", "https://"+appHost("bench")+"/t/bytes?n=100000&len=1", nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			resp, err := s.hub.Do(req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err, "HEAD body")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Empty(t, body)
			require.Equal(t, "100000", resp.Header.Get("Content-Length"))

			// The connection is still good for the next request.
			r2 := s.get(t, appHost("bench"), "/t/static", cookies...)
			readBody(t, r2)
			require.Equal(t, http.StatusOK, r2.StatusCode)
		})
	}
}

// TestLazyReaderPause checks that a browser that stops reading a large
// body for longer than the 30 s idle close gets an error once it reads
// again, and does not hang.
func TestLazyReaderPause(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	const size = 64 << 20
	req, _ := http.NewRequest("GET", "https://"+appHost("bench")+"/t/bytes?len=1&n="+itoa(size), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	cl := s.hub.Client()
	cl.Timeout = 3 * time.Minute
	resp, err := cl.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.CopyN(io.Discard, resp.Body, 1<<20)
	require.NoError(t, err)

	time.Sleep(35 * time.Second)
	start := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	took := time.Since(start)
	t.Logf("read %d more bytes in %v: %v", n, took.Round(100*time.Millisecond), err)
	require.Less(t, took, 60*time.Second, "the read after the pause hung")
	if 1<<20+n < size {
		require.Error(t, err, "the body ended cleanly after %d of %d bytes", 1<<20+n, size)
	}
}

// TestAppSessionOtherHost checks that an app session works only on the
// host it was launched for.
func TestAppSessionOtherHost(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			s := stackFor(t, mode)
			sid, bearer, _ := s.launch(t, s.login(t), "bench")
			cookies := s.handoff(t, "bench", sid, bearer)

			resp := s.get(t, appHost("cam"), "/t/static", cookies...)
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode, "bench's cookies on the cam host")
			require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"))

			body, _ := json.Marshal(map[string]string{"sid": sid, "subject": bearer})
			resp = s.post(t, appHost("cam"), "/x-teleport-auth", origin(appHost("cam")), string(body))
			got := readBody(t, resp)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "bench's session handed off on the cam host")
			require.Equal(t, "bad handoff", string(got))
			require.Nil(t, cookie(resp, "__Host-sp_app"))
		})
	}
}

// TestPoolHubRefusesLazyModes checks that a hub in pool mode answers the
// lazy upgrades to /tunnel/auth with 404.
func TestPoolHubRefusesLazyModes(t *testing.T) {
	logOnFailure(t, shared)
	for _, mode := range []string{"control", "stream"} {
		t.Run(mode, func(t *testing.T) {
			ws, resp, err := shared.DialLazy(t.Context(), mode, http.Header{StreamIDHeader: {newID(t)}})
			if ws != nil {
				ws.Close()
			}
			require.Error(t, err)
			require.NotNil(t, resp)
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}
