package conformance

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AppSession logs Alice in on h with the fake auth, launches app through
// its app host, as the dashboard's launch link does, and posts the handoff.
// It returns the app session ID and bearer token, which are the values of
// the __Host-sp_app and __Host-sp_subject cookies.
func AppSession(h *Hub, app string) (sid, bearer string, err error) {
	post := func(host, path, body string, cookie *http.Cookie) (*http.Response, error) {
		req, err := http.NewRequest("POST", "https://"+host+path, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Origin", "https://"+host)
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := h.Do(req)
		if err != nil {
			return nil, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp, nil
	}

	resp, err := post(LoginHost, "/webapi/login/finish", Assertion("https://"+LoginHost, AliceCredID, nil), nil)
	if err != nil {
		return "", "", err
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-sp_session" {
			session = c
		}
	}
	if resp.StatusCode != http.StatusOK || session == nil {
		return "", "", fmt.Errorf("login: status %d", resp.StatusCode)
	}

	get := func(rawURL, site string, cookie *http.Cookie) (*http.Response, error) {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Sec-Fetch-Site", site)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := h.Do(req)
		if err != nil {
			return nil, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			return nil, fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
		}
		return resp, nil
	}

	resp, err = get("https://"+LoginHost+"/web/launch/"+app, "same-origin", session)
	if err != nil {
		return "", "", err
	}
	resp, err = get(resp.Header.Get("Location"), "same-site", nil)
	if err != nil {
		return "", "", err
	}
	var state *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "__Host-sp_state_") {
			state = c
		}
	}
	if state == nil {
		return "", "", errors.New("launch: no state cookie")
	}
	launch := resp.Header.Get("Location")
	resp, err = get(launch, "same-site", session)
	if err != nil {
		return "", "", err
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(loc.Fragment, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("launch: location %q", resp.Header.Get("Location"))
	}
	sid, bearer = parts[0], parts[1]

	body, _ := json.Marshal(map[string]string{"sid": sid, "subject": bearer, "state": loc.Query().Get("state")})
	resp, err = post(loc.Host, "/x-teleport-auth", string(body), state)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusNoContent {
		return "", "", fmt.Errorf("handoff: status %d", resp.StatusCode)
	}
	return sid, bearer, nil
}

// Assertion is a browser's answer to challenge with the passkey credID, made
// by a page at origin, as the hub's pages send it.
func Assertion(origin, credID string, challenge []byte) string {
	b64 := base64.RawURLEncoding.EncodeToString
	clientData, _ := json.Marshal(map[string]string{"type": "webauthn.get", "origin": origin, "challenge": b64(challenge)})
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
