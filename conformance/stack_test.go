package conformance

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juliaogris/sallyport/conformance/testapp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// stack is a hub of its own with a fake auth behind its callout and an App
// agent that serves the test app.
type stack struct {
	hub   *Hub
	auth  *FakeAuth
	agent *Agent
}

// newStack starts a hub, keeps 4 callout streams open to it, and connects
// an App agent that serves the test app, dialed with opts.
func newStack(t *testing.T, opts ...func(*ssh.ClientConfig)) *stack {
	t.Helper()
	h := freshHub(t)
	auth, err := NewFakeAuth(pki)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	auth.Run(t.Context(), h, 4)

	id, err := pki.AgentIdentity("App")
	require.NoError(t, err)
	a, err := h.DialAgent(t.Context(), pki, id, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { a.Close() })
	require.NoError(t, a.ServeApp(pki, testapp.Handler("")))
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

func itoa(n int) string { return strconv.Itoa(n) }
