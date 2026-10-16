package conformance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

// notFoundBody is the body the test app's mux sends for a path it does not
// serve.
const notFoundBody = "404 page not found\n"

// subStackFor returns a new stack in mode whose hub also serves the app tp,
// in SUB_APPS, at tp.hub.test. SUB_APPS also holds an empty entry and two
// names that are not app names, which the hub drops.
func subStackFor(t *testing.T, mode string) *stack {
	t.Helper()
	vars := BaseVars()
	vars["APPS"] = "bench,cam:/stream,tp:/web"
	vars["SUB_APPS"] = "tp,, Bad,a.b"
	return stackForVars(t, mode, vars)
}

// TestSubApps checks an app in SUB_APPS, served under the login host at
// tp.hub.test: that requests and WebSockets reach the app as they do on
// any app host, which hosts the hub serves, the cookies and the Origin
// checks there, and that the login host's pages stay on the login host.
func TestSubApps(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			testSubApps(t, subStackFor(t, mode))
		})
	}
}

func testSubApps(t *testing.T, s *stack) {
	host := subAppHost("tp")
	session := s.login(t)
	sid, bearer, start := s.launch(t, session, "tp")
	require.Equal(t, "/web", start)
	cookies := s.handoff(t, "tp", sid, bearer)
	for _, c := range cookies {
		requireSessionCookie(t, c)
	}

	t.Run("proxied", func(t *testing.T) {
		e := s.echoAt(t, host, cookies, nil)
		require.Equal(t, Alice, e.Client)
		require.Equal(t, host, e.Host)
		require.Equal(t, "/t/echo?a=1&b=%2F", e.URI)
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

	t.Run("websocket", func(t *testing.T) {
		testAppWebSocket(t, s, host, cookies)
	})

	t.Run("hub cookies stripped", func(t *testing.T) {
		extra := append([]*http.Cookie{{Name: "app", Value: "1"}, session}, cookies...)
		e := s.echoAt(t, host, extra, nil)
		require.Equal(t, []string{"app=1"}, e.Header["Cookie"])

		resp := s.get(t, host, "/t/setcookie", cookies...)
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_app"))
		require.Nil(t, cookie(resp, "__Host-sp_subject"))
		require.NotNil(t, cookie(resp, "app"))
	})

	t.Run("other apps unchanged", func(t *testing.T) {
		resp := s.get(t, appHost("bench"), "/t/static", s.appCookies(t, "bench")...)
		require.Equal(t, testapp.StaticBody, readBody(t, resp))
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("no cookies", func(t *testing.T) {
		for _, c := range [][]*http.Cookie{nil, {session}} {
			resp := s.get(t, host, "/t/static", c...)
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode)
			require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"))
		}
	})

	t.Run("not served at tp-hub.test", func(t *testing.T) {
		for _, c := range [][]*http.Cookie{nil, cookies} {
			resp := s.get(t, appHost("tp"), "/t/static", c...)
			readBody(t, resp)
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		}
	})

	t.Run("other hosts under the login host", func(t *testing.T) {
		for _, h := range []string{
			"bench.hub.test", "cam.hub.test", "x.hub.test", "a.tp.hub.test",
			"tp.bench-hub.test", ".hub.test", "tp..hub.test",
			"Bad.hub.test", "bad.hub.test", "a.b.hub.test",
		} {
			resp, err := s.hub.Get(h, "/t/static")
			require.NoError(t, err, h)
			readBody(t, resp)
			require.Equal(t, http.StatusNotFound, resp.StatusCode, h)
		}
	})

	t.Run("app session only on its host", func(t *testing.T) {
		benchSID, benchBearer, _ := s.launch(t, s.login(t), "bench")
		bench := s.handoff(t, "bench", benchSID, benchBearer)
		for _, tt := range []struct {
			host    string
			cookies []*http.Cookie
		}{
			{appHost("bench"), cookies},
			{host, bench},
		} {
			resp := s.get(t, tt.host, "/t/static", tt.cookies...)
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode, tt.host)
			require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"), tt.host)
		}
		for _, tt := range []struct{ host, sid, bearer string }{
			{appHost("bench"), sid, bearer},
			{host, benchSID, benchBearer},
		} {
			body, _ := json.Marshal(map[string]string{"sid": tt.sid, "subject": tt.bearer})
			resp := s.post(t, tt.host, "/x-teleport-auth", origin(tt.host), string(body))
			require.Equal(t, "bad handoff", string(readBody(t, resp)), tt.host)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, tt.host)
			require.Nil(t, cookie(resp, "__Host-sp_app"))
		}
	})

	t.Run("post from another origin", func(t *testing.T) {
		for _, o := range []string{origin(LoginHost), origin(appHost("bench")), origin(appHost("tp")), "https://other.test"} {
			resp := s.post(t, host, "/t/echo", o, "posted", cookies...)
			readBody(t, resp)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "origin %s", o)

			body, _ := json.Marshal(map[string]string{"sid": sid, "subject": bearer})
			resp = s.post(t, host, "/x-teleport-auth", o, string(body))
			readBody(t, resp)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "handoff from origin %s", o)
			require.Nil(t, cookie(resp, "__Host-sp_app"))
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

	t.Run("login pages not served at tp", func(t *testing.T) {
		gets := []string{
			"/", "/web/login", "/web/passkeys", "/web/add-passkey",
			"/web/invite/x", "/web/launch/bench", "/webapi/passkeys", "/webapi/find", "/webapi/ping",
		}
		posts := []string{
			"/webapi/login/begin", "/webapi/login/finish",
			"/webapi/passkeys/challenge", "/webapi/add-passkey/begin", "/webapi/invite/x/begin",
		}
		for _, p := range gets {
			resp := s.get(t, host, p, cookies...)
			require.Equal(t, notFoundBody, string(readBody(t, resp)), "GET %s did not reach the app", p)
			require.Equal(t, http.StatusNotFound, resp.StatusCode, p)

			resp = s.get(t, host, p)
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode, "GET %s with no cookies", p)
			require.Equal(t, "https://"+LoginHost+"/", resp.Header.Get("Location"))
		}
		for _, p := range posts {
			resp := s.post(t, host, p, origin(host), `{"id":"`+AliceCredID+`","type":"public-key"}`, cookies...)
			require.Equal(t, notFoundBody, string(readBody(t, resp)), "POST %s did not reach the app", p)
			require.Equal(t, http.StatusNotFound, resp.StatusCode, p)
			require.Nil(t, cookie(resp, "__Host-sp_session"), p)
		}
		for _, p := range []string{"/tunnel/auth", "/webapi/connectionupgrade"} {
			resp := s.failWS(t, host, p, origin(host), cookies...)
			require.Equal(t, http.StatusNotFound, resp.StatusCode, p)
		}
	})

	// A page on tp can ask for the login host's passkeys, and a server can
	// post its answer to the login host with any Origin. Auth would take an
	// answer from tp, so the hub must refuse it before it asks auth.
	t.Run("login host refuses passkey answers from tp", func(t *testing.T) {
		logins := countCalls(s.auth, "/v2/users//web/authenticate")
		resp := s.post(t, LoginHost, "/webapi/login/finish", origin(LoginHost), Assertion(origin(host), AliceCredID, nil))
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_session"))
		require.Equal(t, logins, countCalls(s.auth, "/v2/users//web/authenticate"), "the hub asked auth about tp's answer")

		answer := Assertion(origin(host), AliceCredID, s.passkeyChallenge(t, session).challenge(t))
		before := len(s.auth.Calls())
		for path, body := range map[string]string{
			"/webapi/passkeys/begin":  answer,
			"/webapi/passkeys/link":   answer,
			"/webapi/passkeys/delete": passkeyDelete(AliceDevice, answer),
		} {
			resp := s.post(t, LoginHost, path, origin(LoginHost), body, session)
			readBody(t, resp)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, path)
		}
		// Each passkey route checks the web session with auth first.
		for _, c := range s.auth.Calls()[before:] {
			require.Equal(t, "/proto.AuthService/GetWebSession", c.Path)
		}

		cred, _ := json.Marshal(newCredentialFrom(origin(host), BobCredID))
		resp = s.post(t, LoginHost, "/webapi/invite/"+BobInvite+"/finish", origin(LoginHost), string(cred))
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_session"))
		require.Zero(t, countCalls(s.auth, "/proto.AuthService/ChangeUserAuthentication"))
	})

	t.Run("hub pages not framed", func(t *testing.T) {
		for _, tt := range []struct{ host, path string }{
			{LoginHost, "/web/login"},
			{LoginHost, "/web/invite/x"},
			{LoginHost, "/web/add-passkey"},
			{host, "/x-teleport-auth"},
		} {
			resp := s.get(t, tt.host, tt.path)
			readBody(t, resp)
			require.Equal(t, http.StatusOK, resp.StatusCode, tt.path)
			require.Equal(t, "frame-ancestors 'none'", resp.Header.Get("Content-Security-Policy"), tt.path)
			require.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"), tt.path)
		}
	})

	// A web terminal can be quiet for minutes. wrangler dev does not close
	// an idle WebSocket as the Cloudflare edge may, so this checks only the
	// hub's own timers over several of their periods.
	t.Run("quiet terminal for 150 s", func(t *testing.T) {
		if !*long {
			t.Skip("quiet for 150 s; run with -long")
		}
		ws, _ := s.dialWS(t, host, "/t/ws", origin(host), cookies...)
		time.Sleep(150 * time.Second)
		for i := range 3 {
			msg := "still there " + itoa(i)
			require.NoError(t, ws.SetWriteDeadline(time.Now().Add(10*time.Second)))
			require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, []byte(msg)))
			require.NoError(t, ws.SetReadDeadline(time.Now().Add(10*time.Second)))
			_, got, err := ws.ReadMessage()
			require.NoError(t, err)
			require.Equal(t, msg, string(got))
		}
	})
}
