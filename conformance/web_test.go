package conformance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWeb checks the login host and the launch handoff, with the fake
// auth behind the callout.
func TestWeb(t *testing.T) {
	s := newStack(t)
	b64 := base64.RawURLEncoding.EncodeToString

	t.Run("login begin", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/login/begin", origin(LoginHost), "")
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
		require.JSONEq(t, `{
			"challenge": "`+b64(s.auth.LoginChallenge)+`",
			"rpId": "hub.test",
			"timeout": 60000,
			"userVerification": "required",
			"allowCredentials": [{"type": "public-key", "id": "`+b64([]byte(AliceCredID))+`"}]
		}`, string(body))
	})

	t.Run("login finish", func(t *testing.T) {
		c := s.login(t)
		require.True(t, strings.HasPrefix(c.Value, Alice+":"), "cookie %q", c.Value)
		requireSessionCookie(t, c)
	})

	t.Run("login finish refused", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/login/finish", origin(LoginHost), loginAssertion("cred-mallory"))
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_session"))
	})

	t.Run("login finish with an empty assertion", func(t *testing.T) {
		before := countCalls(s.auth, "/v2/users//web/authenticate")
		resp := s.post(t, LoginHost, "/webapi/login/finish", origin(LoginHost), `{}`)
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_session"))
		require.Equal(t, before, countCalls(s.auth, "/v2/users//web/authenticate"), "the hub asked auth about an empty assertion")
	})

	for _, path := range []string{"/webapi/login/begin", "/webapi/login/finish", "/web/logout", "/webapi/invite/" + BobInvite + "/begin"} {
		// An http:// Origin is not tested, because wrangler dev rewrites
		// the scheme of Origin to its own.
		for _, o := range []string{"", "https://other.test", origin(appHost("bench")), origin(subAppHost("tp"))} {
			t.Run("origin "+o+" "+path, func(t *testing.T) {
				resp := s.post(t, LoginHost, path, o, `{"id":"`+AliceCredID+`"}`)
				readBody(t, resp)
				require.Equal(t, http.StatusForbidden, resp.StatusCode)
				require.Nil(t, cookie(resp, "__Host-sp_session"))
			})
		}
	}

	t.Run("invite", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/invite/"+BobInvite+"/begin", origin(LoginHost), "")
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
		require.JSONEq(t, `{
			"challenge": "`+b64(s.auth.RegisterChallenge)+`",
			"rp": {"id": "hub.test", "name": "sallyport"},
			"user": {"id": "`+b64([]byte("user-bob"))+`", "name": "bob", "displayName": "bob"},
			"pubKeyCredParams": [{"type": "public-key", "alg": -7}],
			"timeout": 60000,
			"excludeCredentials": [],
			"attestation": "none",
			"authenticatorSelection": {"requireResidentKey": true, "residentKey": "required", "userVerification": "required"}
		}`, string(body))

		cred, _ := json.Marshal(newCredential(BobCredID))
		resp = s.post(t, LoginHost, "/webapi/invite/"+BobInvite+"/finish", origin(LoginHost), string(cred))
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		c := cookie(resp, "__Host-sp_session")
		require.NotNil(t, c)
		require.True(t, strings.HasPrefix(c.Value, Bob+":"), "cookie %q", c.Value)
		requireSessionCookie(t, c)
	})

	t.Run("invite unknown token", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/invite/tok-nobody/begin", origin(LoginHost), "")
		readBody(t, resp)
		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("dashboard", func(t *testing.T) {
		resp := s.get(t, LoginHost, "/")
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))

		resp = s.get(t, LoginHost, "/", s.login(t))
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, string(body), `href="/web/launch/bench"`)
		require.Contains(t, string(body), `href="/web/launch/cam"`)
	})

	t.Run("logout", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/web/logout", origin(LoginHost), "", s.login(t))
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		c := cookie(resp, "__Host-sp_session")
		require.NotNil(t, c)
		require.Empty(t, c.Value)
		require.Equal(t, -1, c.MaxAge, "cookie not expired")
	})

	t.Run("logout ends the sessions", func(t *testing.T) {
		session := s.login(t)
		sid, bearer, _ := s.launch(t, session, "bench")
		app := s.handoff(t, "bench", sid, bearer)
		before := len(s.auth.Calls())

		resp := s.post(t, LoginHost, "/web/logout", origin(LoginHost), "", session)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		var deletes []string
		for _, c := range s.auth.Calls()[before:] {
			if slices.Contains(logoutDeletes, c.Path) {
				require.Equal(t, Alice, c.Client, "%s not called as the user", c.Path)
				deletes = append(deletes, c.Path)
			}
		}
		require.Equal(t, logoutDeletes, deletes)

		resp = s.get(t, LoginHost, "/", session)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))

		resp = s.get(t, appHost("bench"), "/", app...)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"))
	})

	t.Run("logout without a session", func(t *testing.T) {
		bad := &http.Cookie{Name: "__Host-sp_session", Value: Alice + ":nope"}
		for _, cookies := range [][]*http.Cookie{nil, {bad}} {
			before := len(s.auth.Calls())
			resp := s.post(t, LoginHost, "/web/logout", origin(LoginHost), "", cookies...)
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode)
			c := cookie(resp, "__Host-sp_session")
			require.NotNil(t, c)
			require.Equal(t, -1, c.MaxAge, "cookie not expired")
			for _, c := range s.auth.Calls()[before:] {
				require.NotContains(t, logoutDeletes, c.Path)
			}
		}
	})

	t.Run("handoff after logout", func(t *testing.T) {
		session := s.login(t)
		sid, bearer, _ := s.launch(t, session, "bench")
		resp := s.post(t, LoginHost, "/web/logout", origin(LoginHost), "", session)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)

		resp = s.handoffResp(t, "bench", sid, bearer)
		require.Equal(t, "bad handoff", strings.TrimSpace(string(readBody(t, resp))))
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_app"))
	})

	t.Run("launch", func(t *testing.T) {
		session := s.login(t)
		sid, bearer, start := s.launch(t, session, "bench")
		require.NotEmpty(t, sid)
		require.NotEmpty(t, bearer)
		require.Equal(t, "/", start)
		_, _, start = s.launch(t, session, "cam")
		require.Equal(t, "/stream", start)

		var asUser bool
		for _, c := range s.auth.Calls() {
			if c.Path == "/proto.AuthService/CreateAppSession" {
				require.Equal(t, Alice, c.Client, "CreateAppSession not called as the user")
				asUser = true
			}
		}
		require.True(t, asUser, "no CreateAppSession call")
	})

	t.Run("launch state cookie", func(t *testing.T) {
		_, c := s.startLaunch(t, "bench")
		require.Equal(t, "/", c.Path)
		require.Empty(t, c.Domain)
		require.True(t, c.Secure)
		require.True(t, c.HttpOnly)
		require.Equal(t, http.SameSiteLaxMode, c.SameSite)
		require.Equal(t, 60, c.MaxAge)
	})

	t.Run("launch unknown app", func(t *testing.T) {
		state, _ := s.startLaunch(t, "bench")
		for _, path := range []string{"nope", "nope?state=" + state} {
			resp := s.launchFrom(t, path, "same-site", s.login(t))
			readBody(t, resp)
			require.Equal(t, http.StatusNotFound, resp.StatusCode, path)
		}
	})

	t.Run("launch without session", func(t *testing.T) {
		state, _ := s.startLaunch(t, "bench")
		resp := s.launchFrom(t, "bench?state="+state, "same-site")
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))
	})

	t.Run("launch without state", func(t *testing.T) {
		before := countCalls(s.auth, "/proto.AuthService/CreateAppSession")
		resp := s.launchFrom(t, "bench", "cross-site", s.login(t))
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "https://"+appHost("bench")+"/x-teleport-auth", resp.Header.Get("Location"))
		require.Equal(t, before, countCalls(s.auth, "/proto.AuthService/CreateAppSession"))
	})

	t.Run("launch with a bad state", func(t *testing.T) {
		session := s.login(t)
		before := countCalls(s.auth, "/proto.AuthService/CreateAppSession")
		for _, state := range []string{"x", "a_b", strings.Repeat("a", 64), strings.Repeat("a", 64) + "_" + strings.Repeat("g", 64)} {
			resp := s.launchFrom(t, "bench?state="+state, "same-site", session)
			readBody(t, resp)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, state)
		}
		require.Equal(t, before, countCalls(s.auth, "/proto.AuthService/CreateAppSession"))
	})

	t.Run("launch from another site", func(t *testing.T) {
		session := s.login(t)
		state, _ := s.startLaunch(t, "bench")
		before := countCalls(s.auth, "/proto.AuthService/CreateAppSession")
		for _, site := range []string{"", "none", "cross-site"} {
			resp := s.launchFrom(t, "bench?state="+state, site, session)
			readBody(t, resp)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "Sec-Fetch-Site %q", site)
		}
		req, _ := http.NewRequest("GET", "https://"+LoginHost+"/web/launch/bench?state="+state, nil)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Purpose", "prefetch")
		req.AddCookie(session)
		resp, err := s.hub.Do(req)
		require.NoError(t, err)
		readBody(t, resp)
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "prefetch")
		resp = s.post(t, LoginHost, "/web/launch/bench", origin(LoginHost), "", session)
		readBody(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "POST")
		require.Equal(t, before, countCalls(s.auth, "/proto.AuthService/CreateAppSession"))
	})

	t.Run("handoff", func(t *testing.T) {
		sid, bearer, _ := s.launch(t, s.login(t), "bench")
		for _, c := range s.handoff(t, "bench", sid, bearer) {
			requireSessionCookie(t, c)
		}
	})

	t.Run("handoff clears the state cookie", func(t *testing.T) {
		sid, bearer, _ := s.launch(t, s.login(t), "bench")
		state, sc := s.stateOf(t, sid)
		resp := s.post(t, appHost("bench"), "/x-teleport-auth", origin(appHost("bench")), handoffJSON(sid, bearer, state), sc)
		readBody(t, resp)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		c := cookie(resp, sc.Name)
		require.NotNil(t, c, "state cookie not cleared")
		require.Equal(t, -1, c.MaxAge)
	})

	t.Run("handoff without the launch state", func(t *testing.T) {
		sid, bearer, _ := s.launch(t, s.login(t), "bench")
		state, sc := s.stateOf(t, sid)
		other, oc := s.startLaunch(t, "bench")
		secret, id, _ := strings.Cut(state, "_")
		wrongSecret := &http.Cookie{Name: sc.Name, Value: strings.Repeat("0", len(secret))}
		cases := []struct {
			name, state string
			cookies     []*http.Cookie
		}{
			{"no state cookie", state, nil},
			{"no state", "", []*http.Cookie{sc}},
			{"wrong secret", state, []*http.Cookie{wrongSecret}},
			{"state of another launch", other, []*http.Cookie{sc}},
			{"cookie of another launch", state, []*http.Cookie{oc}},
			{"bad state", secret + id, []*http.Cookie{sc}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				resp := s.post(t, appHost("bench"), "/x-teleport-auth", origin(appHost("bench")), handoffJSON(sid, bearer, c.state), c.cookies...)
				require.Equal(t, "bad handoff", string(readBody(t, resp)))
				require.Equal(t, http.StatusForbidden, resp.StatusCode)
				require.Nil(t, cookie(resp, "__Host-sp_app"))
			})
		}
	})

	t.Run("handoff refused", func(t *testing.T) {
		sid, bearer, _ := s.launch(t, s.login(t), "bench")
		state, sc := s.stateOf(t, sid)
		good := handoffJSON(sid, bearer, state)
		wrong := handoffJSON(sid, "x"+bearer[1:], state)
		cases := []struct {
			name, origin, body string
			status             int
		}{
			{"wrong subject", origin(appHost("bench")), wrong, http.StatusForbidden},
			{"not json", origin(appHost("bench")), "sid=x", http.StatusBadRequest},
			{"empty", origin(appHost("bench")), `{}`, http.StatusBadRequest},
			{"login host origin", origin(LoginHost), good, http.StatusForbidden},
			{"sibling app origin", origin(appHost("cam")), good, http.StatusForbidden},
			{"no origin", "", good, http.StatusForbidden},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				resp := s.post(t, appHost("bench"), "/x-teleport-auth", c.origin, c.body, sc)
				readBody(t, resp)
				require.Equal(t, c.status, resp.StatusCode)
				require.Nil(t, cookie(resp, "__Host-sp_app"))
			})
		}
	})

	t.Run("expired web session", func(t *testing.T) {
		session := s.login(t)
		s.auth.ExpireWebSessions()
		resp := s.get(t, LoginHost, "/", session)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))
	})
}

// requireSessionCookie checks the attributes every hub cookie has.
func requireSessionCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	require.True(t, strings.HasPrefix(c.Name, "__Host-sp_"), c.Name)
	require.True(t, c.Secure, "%s not Secure", c.Name)
	require.True(t, c.HttpOnly, "%s not HttpOnly", c.Name)
	require.Equal(t, "/", c.Path)
	require.Empty(t, c.Domain)
	require.Equal(t, http.SameSiteLaxMode, c.SameSite)
}

// countCalls returns how many calls to path the fake auth has answered.
// logoutDeletes are the calls a logout makes to end the user's sessions.
var logoutDeletes = []string{"/proto.AuthService/DeleteUserAppSessions", "/proto.AuthService/DeleteWebSession"}

func countCalls(a *FakeAuth, path string) int {
	n := 0
	for _, c := range a.Calls() {
		if c.Path == path {
			n++
		}
	}
	return n
}
