package conformance

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/juliaogris/sallyport/conformance/testapp"
	"github.com/stretchr/testify/require"
)

// TestAppProxy checks requests from a logged-in browser to an app host,
// forwarded through the tunnel to the app service.
func TestAppProxy(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	host := appHost("bench")

	t.Run("static", func(t *testing.T) {
		resp := s.get(t, host, "/t/static", cookies...)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, testapp.StaticBody, body)
		require.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
	})

	t.Run("user certificate", func(t *testing.T) {
		e := s.echo(t, cookies, nil)
		require.Equal(t, Alice, e.Client)
		require.Equal(t, host, e.Host)
		require.Equal(t, "/t/echo?a=1&b=%2F", e.URI)
	})

	for _, code := range []int{204, 205, 304} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			resp := s.get(t, host, "/t/status/"+itoa(code), cookies...)
			body := readBody(t, resp)
			require.Equal(t, code, resp.StatusCode)
			require.Empty(t, body)
			require.Equal(t, `"v1"`, resp.Header.Get("ETag"))
		})
	}

	t.Run("gzip passed through", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://"+host+"/t/gzip", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		// A Transport with compression off returns the body as sent.
		cl := s.hub.Client()
		cl.Transport.(*http.Transport).DisableCompression = true
		resp, err := cl.Do(req)
		require.NoError(t, err)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
		zr, err := gzip.NewReader(bytes.NewReader(body))
		require.NoError(t, err, "body is not gzip, compressed twice or not at all")
		plain, err := io.ReadAll(zr)
		require.NoError(t, err)
		require.Equal(t, testapp.GzipPlain, plain)
	})

	t.Run("hub cookies stripped upstream", func(t *testing.T) {
		extra := append([]*http.Cookie{{Name: "app", Value: "1"}}, cookies...)
		extra = append(extra, &http.Cookie{Name: "__Host-sp_session", Value: "alice:x"})
		e := s.echo(t, extra, nil)
		require.Equal(t, []string{"app=1"}, e.Header["Cookie"])
	})

	t.Run("hop-by-hop headers dropped upstream", func(t *testing.T) {
		e := s.echo(t, cookies, http.Header{
			"Keep-Alive":       {"timeout=5"},
			"Proxy-Connection": {"keep-alive"},
			"Te":               {"trailers"},
			"Upgrade":          {"h2c"},
			"X-Kept":           {"yes"},
		})
		for _, h := range []string{"Keep-Alive", "Proxy-Connection", "Te", "Upgrade", "Trailer"} {
			require.NotContains(t, e.Header, h)
		}
		require.Equal(t, []string{"yes"}, e.Header["X-Kept"])
	})

	t.Run("hub cookies dropped from the app's response", func(t *testing.T) {
		resp := s.get(t, host, "/t/setcookie", cookies...)
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_app"))
		require.Nil(t, cookie(resp, "__Host-sp_subject"))
		require.NotNil(t, cookie(resp, "app"))
	})

	t.Run("post", func(t *testing.T) {
		resp := s.post(t, host, "/t/echo", origin(host), "posted", cookies...)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var e testapp.Echo
		require.NoError(t, json.Unmarshal(body, &e))
		require.Equal(t, "POST", e.Method)
		require.Equal(t, "posted", e.Body)
	})

	t.Run("post from another site", func(t *testing.T) {
		for _, o := range []string{origin(appHost("cam")), origin(LoginHost), "https://other.test"} {
			resp := s.post(t, host, "/t/echo", o, "posted", cookies...)
			readBody(t, resp)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "origin %s", o)
		}
		req, _ := http.NewRequest("POST", "https://"+host+"/t/echo", nil)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := s.hub.Do(req)
		require.NoError(t, err)
		readBody(t, resp)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("no cookies", func(t *testing.T) {
		resp := s.get(t, host, "/t/static")
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"))
	})

	t.Run("wrong subject", func(t *testing.T) {
		bad := []*http.Cookie{cookies[0], {Name: "__Host-sp_subject", Value: "nope"}}
		resp := s.get(t, host, "/t/static", bad...)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	})

	t.Run("16 MiB streamed", func(t *testing.T) {
		const n = 16 << 20
		resp := s.get(t, host, "/t/bytes?n="+itoa(n), cookies...)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		want := sha256.New()
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = byte(i)
		}
		for left := n; left > 0; left -= len(chunk) {
			want.Write(chunk[:min(left, len(chunk))])
		}
		got := sha256.New()
		m, err := io.Copy(got, resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, n, m)
		require.Equal(t, want.Sum(nil), got.Sum(nil))
	})
}

// echo sends GET /t/echo?a=1&b=%2F to bench with cookies and extra headers
// and returns what the app saw.
func (s *stack) echo(t *testing.T, cookies []*http.Cookie, header http.Header) testapp.Echo {
	t.Helper()
	return s.echoAt(t, appHost("bench"), cookies, header)
}

// TestAppProxyExpired checks that an expired app session sends the browser
// back to the login host.
func TestAppProxyExpired(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	s.auth.ExpireAppSessions()
	resp := s.get(t, appHost("bench"), "/t/static", cookies...)
	readBody(t, resp)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"))
}

// TestAppProxyOffline checks that with no App tunnel the hub answers 503.
func TestAppProxyOffline(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	s.agent.Close()
	time.Sleep(time.Second)
	resp := s.get(t, appHost("bench"), "/t/static", cookies...)
	readBody(t, resp)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestAuthUnavailable checks that with no callout stream the hub answers
// 503 for an app request and does not hang.
func TestAuthUnavailable(t *testing.T) {
	s := newStack(t)
	cookies := s.appCookies(t, "bench")
	s.auth.Close()
	time.Sleep(time.Second)
	start := time.Now()
	resp := s.get(t, appHost("bench"), "/t/static", cookies...)
	readBody(t, resp)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Less(t, time.Since(start), 15*time.Second)
}
