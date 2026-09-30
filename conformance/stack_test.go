package conformance

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stack is a hub of its own with a fake auth behind its callout and an App
// agent that serves testApp.
type stack struct {
	hub   *Hub
	auth  *FakeAuth
	agent *Agent
}

// newStack starts a hub, keeps 4 callout streams open to it, and connects
// an App agent that serves testApp.
func newStack(t *testing.T) *stack {
	t.Helper()
	h := freshHub(t)
	auth, err := NewFakeAuth(pki)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	auth.Run(t.Context(), h, 4)

	id, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	a, err := h.DialAgent(t.Context(), pki, id)
	require.NoError(t, err)
	t.Cleanup(func() { a.Close() })
	require.NoError(t, a.ServeApp(pki, testApp()))
	_, ok, err := a.Heartbeat()
	require.NoError(t, err)
	require.True(t, ok)

	s := &stack{hub: h, auth: auth, agent: a}
	// The hub registers the tunnel after it answers the first ping, and
	// takes callout streams once they are verified.
	time.Sleep(time.Second)
	return s
}

// appHost returns the app host of app.
func appHost(app string) string { return app + "-" + LoginHost }

// post sends a POST with Origin set to origin, unless origin is "".
func (s *stack) post(t *testing.T, host, path, origin, body string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://"+host+path, strings.NewReader(body))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := s.hub.Do(req)
	require.NoError(t, err)
	return resp
}

// get sends a GET with cookies.
func (s *stack) get(t *testing.T, host, path string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+host+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := s.hub.Do(req)
	require.NoError(t, err)
	return resp
}

func origin(host string) string { return "https://" + host }

// cookie returns the cookie called name that resp sets, or nil.
func cookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return b
}

// login logs Alice in and returns the session cookie.
func (s *stack) login(t *testing.T) *http.Cookie {
	t.Helper()
	resp := s.post(t, LoginHost, "/webapi/login/finish", origin(LoginHost), `{"id":"`+AliceCredID+`","type":"public-key"}`)
	readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	c := cookie(resp, "__Host-sp_session")
	require.NotNil(t, c, "no session cookie")
	return c
}

// launch launches app and returns the app session ID, the bearer token
// and the start path from the handoff URL.
func (s *stack) launch(t *testing.T, session *http.Cookie, app string) (sid, bearer, start string) {
	t.Helper()
	resp := s.post(t, LoginHost, "/web/launch/"+app, origin(LoginHost), "", session)
	readBody(t, resp)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https", loc.Scheme)
	require.Equal(t, appHost(app), loc.Host)
	require.Equal(t, "/x-teleport-auth", loc.Path)
	parts := strings.Split(loc.Fragment, ".")
	require.Len(t, parts, 3, "fragment %q", loc.Fragment)
	p, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	return parts[0], parts[1], string(p)
}

// handoff posts the handoff to the app host and returns the app cookies.
func (s *stack) handoff(t *testing.T, app, sid, bearer string) []*http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"sid": sid, "subject": bearer})
	resp := s.post(t, appHost(app), "/x-teleport-auth", origin(appHost(app)), string(body))
	readBody(t, resp)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	a, sub := cookie(resp, "__Host-sp_app"), cookie(resp, "__Host-sp_subject")
	require.NotNil(t, a)
	require.NotNil(t, sub)
	return []*http.Cookie{a, sub}
}

// appCookies logs in, launches app and returns its cookies.
func (s *stack) appCookies(t *testing.T, app string) []*http.Cookie {
	t.Helper()
	sid, bearer, _ := s.launch(t, s.login(t), app)
	return s.handoff(t, app, sid, bearer)
}

// The bodies testApp serves.
var (
	staticBody = []byte("hello from the app\n")
	gzipPlain  = []byte("hello, gzipped\n")
)

// testApp is the app behind the fake agent.
func testApp() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/static", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(staticBody)))
		w.Write(staticBody)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = byte(i)
		}
		for n > 0 {
			k := min(n, len(chunk))
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write(gzipPlain)
		zw.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
		w.Write(b.Bytes())
	})
	for _, code := range []int{204, 205, 304} {
		mux.HandleFunc(fmt.Sprintf("/status/%d", code), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(code)
		})
	}
	// A 101 with no Upgrade in the request, which no hub can forward.
	mux.HandleFunc("/status/101", func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		conn.Close()
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		client := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			client = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(echo{
			Method: r.Method, Host: r.Host, URI: r.RequestURI,
			Header: r.Header, Body: string(body), Client: client,
		})
	})
	mux.HandleFunc("/setcookie", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "__Host-sp_app=evil; Path=/; Secure")
		w.Header().Add("Set-Cookie", "__Host-sp_subject=evil; Path=/; Secure")
		w.Header().Add("Set-Cookie", "app=1; Path=/")
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// echo is what testApp's /echo returns.
type echo struct {
	Method string
	Host   string
	URI    string
	Header http.Header
	Body   string
	Client string
}

func itoa(n int) string { return strconv.Itoa(n) }
