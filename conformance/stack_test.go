package conformance

import (
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
	// sub are the apps in the hub's SUB_APPS.
	sub map[string]bool
}

// newStack starts a hub, keeps 4 callout streams open to it, and connects
// an App agent that serves the test app, dialed with opts.
func newStack(t *testing.T, opts ...func(*ssh.ClientConfig)) *stack {
	t.Helper()
	return newStackVars(t, BaseVars(), opts...)
}

// newStackVars is newStack for a hub that runs with vars.
func newStackVars(t *testing.T, vars map[string]string, opts ...func(*ssh.ClientConfig)) *stack {
	t.Helper()
	h := freshHubVars(t, vars)
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

	s := &stack{hub: h, auth: auth, agent: a, sub: subApps(vars)}
	// The hub registers the tunnel after it answers the first ping, and
	// takes callout streams once they are verified.
	time.Sleep(time.Second)
	return s
}

// appHost returns the app host of app.
func appHost(app string) string { return app + "-" + LoginHost }

// subAppHost returns the host of app when it is in SUB_APPS.
func subAppHost(app string) string { return app + "." + LoginHost }

// hostOf returns the host the hub serves app at.
func (s *stack) hostOf(app string) string {
	if s.sub[app] {
		return subAppHost(app)
	}
	return appHost(app)
}

// subApps returns the apps in the SUB_APPS of vars.
func subApps(vars map[string]string) map[string]bool {
	m := make(map[string]bool)
	for _, n := range strings.Split(vars["SUB_APPS"], ",") {
		if n != "" {
			m[n] = true
		}
	}
	return m
}

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

// launchFrom sends a GET for the launch of app with Sec-Fetch-Site set to
// site, unless site is "".
func (s *stack) launchFrom(t *testing.T, app, site string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+LoginHost+"/web/launch/"+app, nil)
	if site != "" {
		req.Header.Set("Sec-Fetch-Site", site)
	}
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

// login logs Alice in and returns the session cookie. Each login comes
// from its own client address, so that the hubs' login limits per address
// do not refuse tests that log in many times.
func (s *stack) login(t *testing.T) *http.Cookie {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://"+LoginHost+"/webapi/login/finish", strings.NewReader(loginAssertion(AliceCredID)))
	req.Header.Set("Origin", origin(LoginHost))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cf-Connecting-Ip", randomIP())
	resp, err := s.hub.Do(req)
	require.NoError(t, err)
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
	resp := s.launchFrom(t, app, "same-origin", session)
	readBody(t, resp)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https", loc.Scheme)
	require.Equal(t, s.hostOf(app), loc.Host)
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
	resp := s.post(t, s.hostOf(app), "/x-teleport-auth", origin(s.hostOf(app)), string(body))
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

// randomIP returns a random address in 198.18.0.0/15, the benchmarking
// range.
func randomIP() string {
	b := randomBytes(2)
	return fmt.Sprintf("198.%d.%d.%d", 18+int(b[0])%2, b[1], 1+int(b[0])%250)
}
