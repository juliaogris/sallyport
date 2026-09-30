package conformance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
		resp := s.post(LoginHost, "/webapi/login/begin", origin(LoginHost), "")
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
		resp := s.post(LoginHost, "/webapi/login/finish", origin(LoginHost), `{"id":"cred-mallory"}`)
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Nil(t, cookie(resp, "__Host-sp_session"))
	})

	for _, path := range []string{"/webapi/login/begin", "/webapi/login/finish", "/web/launch/bench", "/web/logout", "/webapi/invite/" + BobInvite + "/begin"} {
		// An http:// Origin is not tested, because wrangler dev rewrites
		// the scheme of Origin to its own.
		for _, o := range []string{"", "https://other.test", origin(appHost("bench"))} {
			t.Run("origin "+o+" "+path, func(t *testing.T) {
				resp := s.post(LoginHost, path, o, `{"id":"`+AliceCredID+`"}`)
				readBody(t, resp)
				require.Equal(t, http.StatusForbidden, resp.StatusCode)
				require.Nil(t, cookie(resp, "__Host-sp_session"))
			})
		}
	}

	t.Run("invite", func(t *testing.T) {
		resp := s.post(LoginHost, "/webapi/invite/"+BobInvite+"/begin", origin(LoginHost), "")
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

		cred, _ := json.Marshal(map[string]any{
			"type":  "public-key",
			"rawId": b64([]byte(BobCredID)),
			"response": map[string]string{
				"clientDataJSON":    b64([]byte(`{"type":"webauthn.create"}`)),
				"attestationObject": b64([]byte("attestation")),
			},
		})
		resp = s.post(LoginHost, "/webapi/invite/"+BobInvite+"/finish", origin(LoginHost), string(cred))
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		c := cookie(resp, "__Host-sp_session")
		require.NotNil(t, c)
		require.True(t, strings.HasPrefix(c.Value, Bob+":"), "cookie %q", c.Value)
		requireSessionCookie(t, c)
	})

	t.Run("invite unknown token", func(t *testing.T) {
		resp := s.post(LoginHost, "/webapi/invite/tok-nobody/begin", origin(LoginHost), "")
		readBody(t, resp)
		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("dashboard", func(t *testing.T) {
		resp := s.get(LoginHost, "/")
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))

		resp = s.get(LoginHost, "/", s.login(t))
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, string(body), `action="/web/launch/bench"`)
		require.Contains(t, string(body), `action="/web/launch/cam"`)
	})

	t.Run("logout", func(t *testing.T) {
		resp := s.post(LoginHost, "/web/logout", origin(LoginHost), "", s.login(t))
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		c := cookie(resp, "__Host-sp_session")
		require.NotNil(t, c)
		require.Empty(t, c.Value)
		require.Equal(t, -1, c.MaxAge, "cookie not expired")
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

	t.Run("launch unknown app", func(t *testing.T) {
		resp := s.post(LoginHost, "/web/launch/nope", origin(LoginHost), "", s.login(t))
		readBody(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("launch without session", func(t *testing.T) {
		resp := s.post(LoginHost, "/web/launch/bench", origin(LoginHost), "")
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))
	})

	t.Run("handoff", func(t *testing.T) {
		sid, bearer, _ := s.launch(t, s.login(t), "bench")
		for _, c := range s.handoff(t, "bench", sid, bearer) {
			requireSessionCookie(t, c)
		}
	})

	t.Run("handoff refused", func(t *testing.T) {
		sid, bearer, _ := s.launch(t, s.login(t), "bench")
		good, _ := json.Marshal(map[string]string{"sid": sid, "subject": bearer})
		wrong, _ := json.Marshal(map[string]string{"sid": sid, "subject": "x" + bearer[1:]})
		cases := []struct {
			name, origin, body string
			status             int
		}{
			{"wrong subject", origin(appHost("bench")), string(wrong), http.StatusForbidden},
			{"not json", origin(appHost("bench")), "sid=x", http.StatusBadRequest},
			{"empty", origin(appHost("bench")), `{}`, http.StatusBadRequest},
			{"login host origin", origin(LoginHost), string(good), http.StatusForbidden},
			{"sibling app origin", origin(appHost("cam")), string(good), http.StatusForbidden},
			{"no origin", "", string(good), http.StatusForbidden},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				resp := s.post(appHost("bench"), "/x-teleport-auth", c.origin, c.body)
				readBody(t, resp)
				require.Equal(t, c.status, resp.StatusCode)
				require.Nil(t, cookie(resp, "__Host-sp_app"))
			})
		}
	})

	t.Run("expired web session", func(t *testing.T) {
		session := s.login(t)
		s.auth.ExpireWebSessions()
		resp := s.get(LoginHost, "/", session)
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
