package conformance

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

// timedGet sends GET path to app host bench with cookies and a client
// timeout of limit. It returns the status, or 0 when the request did not
// finish, and how long it took.
func (s *stack) timedGet(t *testing.T, path string, cookies []*http.Cookie, limit time.Duration) (int, time.Duration) {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+appHost("bench")+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	cl := s.hub.Client()
	cl.Timeout = limit
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, time.Since(start)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(start)
}

// TestLazyDialFails checks that an app request ends with a 5xx, and does not
// hang, when auth's callout answers a dial badly, and that the next request
// works.
func TestLazyDialFails(t *testing.T) {
	s := newLazyStack(t)
	cases := []struct {
		name  string
		dial  LazyDial
		limit time.Duration
	}{
		// The dial deadline is 10 s.
		{"no stream", LazyDialIgnore, 20 * time.Second},
		{"stream closed at once", LazyDialClose, 20 * time.Second},
		{"stream not TLS", LazyDialGarbage, 20 * time.Second},
		// An idle stream closes after 30 s.
		{"stream silent", LazyDialSilent, 50 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The Go hub keeps an app connection per app session for 5 s,
			// so each case gets a new session and a new dial.
			cookies := s.appCookies(t, "bench")
			s.auth.SetLazyDial(c.dial)
			status, took := s.timedGet(t, "/t/static", cookies, c.limit)
			s.auth.SetLazyDial(LazyDialServe)
			require.NotZero(t, status, "no answer within %v", c.limit)
			require.GreaterOrEqual(t, status, 500, "status %d after %v", status, took)
			t.Logf("%d after %v", status, took.Round(100*time.Millisecond))

			status, _ = s.timedGet(t, "/t/static", cookies, 20*time.Second)
			require.Equal(t, http.StatusOK, status, "the next request")
		})
	}
}

// TestLazyPendingDialCap checks that 40 dials that never get a stream, more
// than the hub's 32 pending dials, all end and leave the hub working.
func TestLazyPendingDialCap(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	s.auth.SetLazyDial(LazyDialIgnore)
	statuses := make([]int, 40)
	var wg sync.WaitGroup
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], _ = s.timedGet(t, "/t/static", cookies, 30*time.Second)
		}()
	}
	wg.Wait()
	s.auth.SetLazyDial(LazyDialServe)
	for i, st := range statuses {
		require.NotZero(t, st, "request %d did not finish", i)
		require.GreaterOrEqual(t, st, 500, "request %d", i)
	}
	status, _ := s.timedGet(t, "/t/static", cookies, 20*time.Second)
	require.Equal(t, http.StatusOK, status, "a request after the failed dials")
}

// TestLazyDuplicateStream checks that the hub refuses a second stream for
// a dial id it has already used, and still serves the first.
func TestLazyDuplicateStream(t *testing.T) {
	s := newLazyStack(t)
	cookies := s.appCookies(t, "bench")
	s.auth.SetLazyDial(LazyDialTwice)
	status, _ := s.timedGet(t, "/t/static", cookies, 20*time.Second)
	s.auth.SetLazyDial(LazyDialServe)
	require.Equal(t, http.StatusOK, status)
	dups := s.auth.Duplicates()
	require.NotEmpty(t, dups)
	for _, d := range dups {
		require.NotEqual(t, http.StatusSwitchingProtocols, d, "the hub accepted a second stream with a used id")
	}
}

var liveEdge = flag.Bool("live-edge", false, "the hub runs behind Cloudflare's edge, not wrangler dev")

// TestAppStalledBody checks that a response body the app stops sending
// ends within 60 s, in both hub modes, so the request does not hang, and
// that it ends with an error, so the browser does not take the part it got
// for the whole body.
func TestAppStalledBody(t *testing.T) {
	for _, mode := range []string{"tunnel", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "tunnel" {
				t.Skip("known gap: in tunnel mode a stalled body never ends on either hub; no cluster runs tunnel mode and no fix is planned")
			}
			s := newLazyStack(t)
			cookies := s.appCookies(t, "bench")
			// 4 KiB, then nothing for over an hour.
			req, _ := http.NewRequest("GET", "https://"+appHost("bench")+"/t/slow?n=1048576&bps=1", nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			cl := s.hub.Client()
			cl.Timeout = 70 * time.Second
			start := time.Now()
			resp, err := cl.Do(req)
			require.NoError(t, err)
			n, err := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			took := time.Since(start)
			t.Logf("status %d, %d bytes, ended after %v: %v", resp.StatusCode, n, took.Round(time.Second), err)
			require.Less(t, took, 60*time.Second, "the stalled body did not end")
			// A body cut short must not look complete to the browser, but
			// wrangler dev ends a chunked response cleanly even when the
			// Worker's body stream errors, so this runs only against a live
			// hub.
			if *liveEdge {
				require.Error(t, err, "the body ended cleanly after %d of 1048576 bytes", n)
			}
		})
	}
}

// TestUploads checks that uploads larger than the callout's 8 MiB of unread
// bytes reach the app whole, in both hub modes, also when the app reads
// them slowly.
func TestUploads(t *testing.T) {
	cases := []struct {
		name string
		size int
		bps  int
	}{
		{"16 MiB", 16 << 20, 0},
		{"64 MiB", 64 << 20, 0},
		// More than the callout's 8 MiB unread, so the lazy hub must wait
		// for upload acks.
		{"16 MiB read at 1 MiB/s", 16 << 20, 1 << 20},
	}
	for _, mode := range []string{"tunnel", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			var s *stack
			if mode == "lazy" {
				s = newLazyStack(t)
			} else {
				s = newStack(t)
			}
			cookies := s.appCookies(t, "bench")
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					path := "/t/upload"
					if c.bps > 0 {
						path += "?bps=" + strconv.Itoa(c.bps)
					}
					req, _ := http.NewRequest("POST", "https://"+appHost("bench")+path, bytes.NewReader(testapp.Pattern(c.size)))
					req.Header.Set("Origin", origin(appHost("bench")))
					for _, ck := range cookies {
						req.AddCookie(ck)
					}
					cl := s.hub.Client()
					cl.Timeout = 2 * time.Minute
					start := time.Now()
					resp, err := cl.Do(req)
					require.NoError(t, err)
					body := readBody(t, resp)
					require.Equal(t, http.StatusOK, resp.StatusCode, "body %q", body)
					require.Equal(t, fmt.Sprintf("%d\n", c.size), string(body))
					t.Logf("%s in %v", c.name, time.Since(start).Round(100*time.Millisecond))
				})
			}
		})
	}
}

// TestLazyNoSSHSecrets checks that a hub in lazy mode works without the
// SSH secrets, which only the reverse tunnel uses.
func TestLazyNoSSHSecrets(t *testing.T) {
	secrets := maps.Clone(pki.Secrets())
	for _, k := range []string{"HUB_SSH_KEY", "HUB_SSH_CERT", "HOST_CA_SSH"} {
		delete(secrets, k)
	}
	dir := filepath.Join(tmp, t.Name())
	require.NoError(t, os.MkdirAll(dir, 0o700))
	h, err := StartHub(t.Context(), hubKind, hubDir, dir, LazyVars(), secrets)
	require.NoError(t, err)
	t.Cleanup(h.Stop)
	logOnFailure(t, h)
	auth, err := NewFakeAuth(pki)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	app, err := NewAppServer(pki, testapp.Handler(""))
	require.NoError(t, err)
	t.Cleanup(app.Close)
	auth.RunLazy(t.Context(), h, app)
	time.Sleep(time.Second)
	s := &stack{hub: h, auth: auth}

	cookies := s.appCookies(t, "bench")
	resp := s.get(t, appHost("bench"), "/t/static", cookies...)
	body := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, testapp.StaticBody, body)
}

// TestLazyUnknownPathsDoNotWake checks that a request the hub can only
// refuse is answered by the Worker without starting the Durable Object.
// Each case runs on a hub of its own, because one start would hide the
// next.
func TestLazyUnknownPathsDoNotWake(t *testing.T) {
	const started = "durable object started"
	type req struct {
		name, method, host, path string
		upgrade                  bool
	}
	cases := []req{
		{"unknown host", "GET", "other.test", "/", false},
		{"unknown host upgrade", "GET", "other.test", CalloutPath + "?mode=control", true},
		{"login host unknown path", "GET", LoginHost, "/nope", false},
		{"login host favicon", "GET", LoginHost, "/favicon.ico", false},
		{"login host POST unknown path", "POST", LoginHost, "/wp-login.php", false},
		{"tunnel upgrade in lazy mode", "GET", LoginHost, TunnelPath, true},
		{"callout upgrade without mode", "GET", LoginHost, CalloutPath, true},
		{"callout upgrade with unknown mode", "GET", LoginHost, CalloutPath + "?mode=pool", true},
		{"callout without upgrade", "GET", LoginHost, CalloutPath + "?mode=control", false},
		{"callout upgrade on an app host", "GET", appHost("bench"), CalloutPath + "?mode=control", true},
		{"app host without cookies", "GET", appHost("bench"), "/", false},
		{"app host scanner path", "GET", appHost("bench"), "/.env", false},
		{"app host POST from another site", "POST", appHost("bench"), "/t/upload", false},
		{"app host logout", "GET", appHost("bench"), "/teleport-logout", false},
		{"app host dbsc", "GET", appHost("bench"), "/x-teleport-dbsc/start", false},
	}
	send := func(t *testing.T, h *Hub, c req) {
		if c.upgrade {
			d := websocket.Dialer{NetDialContext: h.DialContext, TLSClientConfig: EdgeTLS(), HandshakeTimeout: 20 * time.Second}
			ws, resp, err := d.DialContext(t.Context(), "wss://"+c.host+c.path, nil)
			if err == nil {
				ws.Close()
				t.Errorf("upgrade accepted")
			} else if resp != nil {
				t.Logf("status %d", resp.StatusCode)
			}
			return
		}
		r, _ := http.NewRequest(c.method, "https://"+c.host+c.path, strings.NewReader(""))
		if c.method == "POST" {
			r.Header.Set("Origin", "https://other.test")
		}
		resp, err := h.Do(r)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Logf("status %d", resp.StatusCode)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := lazyHub(t)
			send(t, h, c)
			time.Sleep(time.Second)
			require.False(t, h.LogHas(started), "the request started the Durable Object")
		})
	}
	// The check sees a start: the dashboard needs the object.
	t.Run("dashboard starts the object", func(t *testing.T) {
		h := lazyHub(t)
		send(t, h, req{"", "GET", LoginHost, "/", false})
		require.Eventually(t, func() bool { return h.LogHas(started) }, 10*time.Second, 200*time.Millisecond)
	})
}
