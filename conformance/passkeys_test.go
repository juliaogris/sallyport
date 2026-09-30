package conformance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPasskeys checks the passkey management routes on the login host,
// with the fake auth behind the callout. Alice starts with one passkey and
// the subtests run in order, so each one states what she has.
func TestPasskeys(t *testing.T) {
	s := newStack(t)
	b64 := base64.RawURLEncoding.EncodeToString
	session := s.login(t)

	t.Run("dashboard link", func(t *testing.T) {
		resp := s.get(t, LoginHost, "/", session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, string(body), `<p><a href="/web/passkeys">Passkeys</a></p>`)
	})

	t.Run("page", func(t *testing.T) {
		resp := s.get(t, LoginHost, "/web/passkeys", session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, resp.Header.Get("Content-Type"), "text/html")
		require.Contains(t, string(body), "Add a passkey")
		require.Contains(t, string(body), "/webapi/passkeys/challenge")
	})

	t.Run("list", func(t *testing.T) {
		resp := s.get(t, LoginHost, "/webapi/passkeys", session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
		require.JSONEq(t, `{"passkeys": [{"name": "passkey", "addedAt": "2026-09-01T12:00:00Z"}]}`, string(body))
	})

	t.Run("challenge", func(t *testing.T) {
		c := s.passkeyChallenge(t, session)
		require.Equal(t, RPID, c.RPID)
		require.Equal(t, "required", c.UserVerification)
		require.Len(t, c.AllowCredentials, 1)
		require.Equal(t, b64([]byte(AliceCredID)), c.AllowCredentials[0].ID)
		require.NotEqual(t, s.auth.LoginChallenge, c.challenge(t), "login challenge used for managing passkeys")
		calls := s.auth.Calls()
		last := calls[len(calls)-1]
		require.Equal(t, "/proto.AuthService/CreateAuthenticateChallenge", last.Path)
		require.Equal(t, Alice, last.Client, "challenge not created as the user")
	})

	t.Run("add", func(t *testing.T) {
		answer := s.passkeyAnswer(t, session, AliceCredID)
		resp := s.post(t, LoginHost, "/webapi/passkeys/begin", origin(LoginHost), answer, session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
		require.JSONEq(t, `{
			"challenge": "`+b64(s.auth.RegisterChallenge)+`",
			"rp": {"id": "hub.test", "name": "sallyport"},
			"user": {"id": "`+b64([]byte("user-alice"))+`", "name": "alice", "displayName": "alice"},
			"pubKeyCredParams": [{"type": "public-key", "alg": -7}],
			"timeout": 60000,
			"excludeCredentials": [{"type": "public-key", "id": "`+b64([]byte(AliceCredID))+`"}],
			"attestation": "none",
			"authenticatorSelection": {"requireResidentKey": true, "residentKey": "required", "userVerification": "required"}
		}`, string(body))

		resp = s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), passkeyCredential("laptop", "cred-alice-2"), session)
		body = readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
		require.JSONEq(t, `{"ok": true}`, string(body))

		devices := s.auth.Devices(Alice)
		require.Len(t, devices, 2)
		require.Equal(t, "laptop", devices[1].Name)
		require.Equal(t, "cred-alice-2", devices[1].CredID)

		names, addedAt := s.passkeyList(t, session)
		require.Equal(t, []string{"passkey", "laptop"}, names)
		require.Equal(t, devices[1].AddedAt.UTC().Format("2006-01-02T15:04:05Z"), addedAt[1])
	})

	t.Run("login with the new passkey", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/login/finish", origin(LoginHost), `{"id":"cred-alice-2","type":"public-key"}`)
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		c := cookie(resp, "__Host-sp_session")
		require.NotNil(t, c)
		require.True(t, strings.HasPrefix(c.Value, Alice+":"), "cookie %q", c.Value)
	})

	t.Run("finish without begin", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), passkeyCredential("tablet", "cred-alice-3"), session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "body %s", body)
		require.Equal(t, `session data for user "alice" not found`, string(body))
		require.Len(t, s.auth.Devices(Alice), 2)
	})

	t.Run("used name", func(t *testing.T) {
		s.passkeyBegin(t, session)
		resp := s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), passkeyCredential("laptop", "cred-alice-3"), session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusConflict, resp.StatusCode, "body %s", body)
		require.Equal(t, `MFA device with name "laptop" already exists`, string(body))
		require.Len(t, s.auth.Devices(Alice), 2)
	})

	t.Run("name too long", func(t *testing.T) {
		s.passkeyBegin(t, session)
		resp := s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), passkeyCredential(strings.Repeat("x", 31), "cred-alice-3"), session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body %s", body)
		require.Equal(t, "device name must be 30 characters or less", string(body))
	})

	t.Run("login challenge answer refused", func(t *testing.T) {
		answer := passkeyAssertion(AliceCredID, s.auth.LoginChallenge)
		resp := s.post(t, LoginHost, "/webapi/passkeys/begin", origin(LoginHost), answer, session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "body %s", body)
		require.Contains(t, string(body), "MFA response validation failed")
	})

	t.Run("answer is used up", func(t *testing.T) {
		answer := s.passkeyAnswer(t, session, AliceCredID)
		resp := s.post(t, LoginHost, "/webapi/passkeys/begin", origin(LoginHost), answer, session)
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp = s.post(t, LoginHost, "/webapi/passkeys/begin", origin(LoginHost), answer, session)
		readBody(t, resp)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("remove", func(t *testing.T) {
		answer := s.passkeyAnswer(t, session, AliceCredID)
		resp := s.post(t, LoginHost, "/webapi/passkeys/delete", origin(LoginHost), passkeyDelete("laptop", answer), session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
		require.JSONEq(t, `{"ok": true}`, string(body))
		names, _ := s.passkeyList(t, session)
		require.Equal(t, []string{"passkey"}, names)
	})

	t.Run("remove unknown", func(t *testing.T) {
		s.passkeyAdd(t, session, "phone", "cred-alice-4")
		answer := s.passkeyAnswer(t, session, AliceCredID)
		resp := s.post(t, LoginHost, "/webapi/passkeys/delete", origin(LoginHost), passkeyDelete("nope", answer), session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "body %s", body)
		require.Equal(t, `MFA device "nope" does not exist`, string(body))
		answer = s.passkeyAnswer(t, session, AliceCredID)
		resp = s.post(t, LoginHost, "/webapi/passkeys/delete", origin(LoginHost), passkeyDelete("phone", answer), session)
		readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("remove the last", func(t *testing.T) {
		before := len(s.auth.Calls())
		answer := s.passkeyAnswer(t, session, AliceCredID)
		resp := s.post(t, LoginHost, "/webapi/passkeys/delete", origin(LoginHost), passkeyDelete("passkey", answer), session)
		body := readBody(t, resp)
		require.Equal(t, http.StatusConflict, resp.StatusCode, "body %s", body)
		require.Equal(t, "cannot remove the last passkey", string(body))
		require.Len(t, s.auth.Devices(Alice), 1)
		for _, c := range s.auth.Calls()[before:] {
			require.NotEqual(t, "/proto.AuthService/DeleteMFADeviceSync", c.Path, "auth asked to delete the last passkey")
		}
	})

	t.Run("bad body", func(t *testing.T) {
		for _, path := range []string{"/webapi/passkeys/begin", "/webapi/passkeys/finish", "/webapi/passkeys/delete"} {
			resp := s.post(t, LoginHost, path, origin(LoginHost), "not json", session)
			readBody(t, resp)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, path)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), strings.Repeat("x", bodyLimit), session)
		readBody(t, resp)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "a body of the limit did not reach the hub")
		resp = s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), strings.Repeat("x", bodyLimit+1), session)
		readBody(t, resp)
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	t.Run("rate limited", func(t *testing.T) {
		s.auth.SetRateLimited(true)
		defer s.auth.SetRateLimited(false)
		resp := s.post(t, LoginHost, "/webapi/passkeys/challenge", origin(LoginHost), "", session)
		readBody(t, resp)
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	})

	t.Run("no session", func(t *testing.T) {
		resp := s.get(t, LoginHost, "/web/passkeys")
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, "/web/login", resp.Header.Get("Location"))

		resp = s.get(t, LoginHost, "/webapi/passkeys")
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		for _, path := range passkeyPosts {
			resp := s.post(t, LoginHost, path, origin(LoginHost), "{}")
			readBody(t, resp)
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode, path)
		}
	})

	t.Run("other origin", func(t *testing.T) {
		for _, path := range passkeyPosts {
			for _, o := range []string{"", "https://other.test", origin(appHost("bench"))} {
				resp := s.post(t, LoginHost, path, o, "{}", session)
				readBody(t, resp)
				require.Equal(t, http.StatusForbidden, resp.StatusCode, "%s from %q", path, o)
			}
		}
	})

	t.Run("not found", func(t *testing.T) {
		resp := s.post(t, LoginHost, "/webapi/passkeys/nope", origin(LoginHost), "{}", session)
		readBody(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp = s.get(t, LoginHost, "/webapi/passkeys/challenge", session)
		readBody(t, resp)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	// Last, because it expires every web session of the stack.
	t.Run("expired session", func(t *testing.T) {
		s.auth.ExpireWebSessions()
		resp := s.get(t, LoginHost, "/webapi/passkeys", session)
		readBody(t, resp)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp = s.get(t, LoginHost, "/web/passkeys", session)
		readBody(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	})

	// Last, because it closes the fake auth.
	t.Run("auth unavailable", func(t *testing.T) {
		s.auth.Close()
		time.Sleep(time.Second)
		resp := s.get(t, LoginHost, "/webapi/passkeys", session)
		readBody(t, resp)
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// passkeyPosts are the POST routes for managing passkeys.
var passkeyPosts = []string{"/webapi/passkeys/challenge", "/webapi/passkeys/begin", "/webapi/passkeys/finish", "/webapi/passkeys/delete"}

// bodyLimit is the most bytes a login host request body may have.
const bodyLimit = 64 * 1024

// requestOptions is the JSON a challenge route returns, as the pages read
// it.
type requestOptions struct {
	Challenge        string `json:"challenge"`
	RPID             string `json:"rpId"`
	UserVerification string `json:"userVerification"`
	AllowCredentials []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"allowCredentials"`
}

func (o *requestOptions) challenge(t *testing.T) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(o.Challenge)
	require.NoError(t, err)
	return b
}

// passkeyChallenge asks for a manage-devices challenge.
func (s *stack) passkeyChallenge(t *testing.T, session *http.Cookie) *requestOptions {
	t.Helper()
	resp := s.post(t, LoginHost, "/webapi/passkeys/challenge", origin(LoginHost), "", session)
	body := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
	o := &requestOptions{}
	require.NoError(t, json.Unmarshal(body, o))
	return o
}

// passkeyAnswer asks for a manage-devices challenge and answers it with
// credID.
func (s *stack) passkeyAnswer(t *testing.T, session *http.Cookie, credID string) string {
	t.Helper()
	return passkeyAssertion(credID, s.passkeyChallenge(t, session).challenge(t))
}

// passkeyAssertion is a browser's answer to challenge with the passkey
// credID, as the pages send it. The fake auth reads the challenge from the
// clientDataJSON.
func passkeyAssertion(credID string, challenge []byte) string {
	b64 := base64.RawURLEncoding.EncodeToString
	clientData, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": b64(challenge)})
	v, _ := json.Marshal(map[string]any{
		"id":         credID,
		"rawId":      b64([]byte(credID)),
		"type":       "public-key",
		"extensions": map[string]any{},
		"response": map[string]any{
			"authenticatorData": b64([]byte("authenticator data")),
			"clientDataJSON":    b64(clientData),
			"signature":         b64([]byte("signature")),
			"userHandle":        nil,
		},
	})
	return string(v)
}

// passkeyCredential is the body of a finish: the name and the browser's new
// credential with ID credID.
func passkeyCredential(name, credID string) string {
	b64 := base64.RawURLEncoding.EncodeToString
	v, _ := json.Marshal(map[string]any{
		"name": name,
		"credential": map[string]any{
			"type":  "public-key",
			"rawId": b64([]byte(credID)),
			"response": map[string]string{
				"clientDataJSON":    b64([]byte(`{"type":"webauthn.create"}`)),
				"attestationObject": b64([]byte("attestation")),
			},
		},
	})
	return string(v)
}

// passkeyDelete is the body of a delete: the name and a fresh answer.
func passkeyDelete(name, answer string) string {
	v, _ := json.Marshal(map[string]any{"name": name, "assertion": json.RawMessage(answer)})
	return string(v)
}

// passkeyBegin starts adding a passkey for Alice, confirmed with her first
// passkey.
func (s *stack) passkeyBegin(t *testing.T, session *http.Cookie) {
	t.Helper()
	resp := s.post(t, LoginHost, "/webapi/passkeys/begin", origin(LoginHost), s.passkeyAnswer(t, session, AliceCredID), session)
	body := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
}

// passkeyAdd adds a passkey called name with credID for Alice, confirmed
// with her first passkey.
func (s *stack) passkeyAdd(t *testing.T, session *http.Cookie, name, credID string) {
	t.Helper()
	s.passkeyBegin(t, session)
	resp := s.post(t, LoginHost, "/webapi/passkeys/finish", origin(LoginHost), passkeyCredential(name, credID), session)
	body := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
}

// passkeyList returns the names and addedAt values from the list route.
func (s *stack) passkeyList(t *testing.T, session *http.Cookie) (names, addedAt []string) {
	t.Helper()
	resp := s.get(t, LoginHost, "/webapi/passkeys", session)
	body := readBody(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
	var list struct {
		Passkeys []struct {
			Name    string `json:"name"`
			AddedAt string `json:"addedAt"`
		} `json:"passkeys"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	for _, p := range list.Passkeys {
		names = append(names, p.Name)
		addedAt = append(addedAt, p.AddedAt)
	}
	return names, addedAt
}
