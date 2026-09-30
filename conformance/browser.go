package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AppSession logs Alice in on h with the fake auth, launches app and posts
// the handoff. It returns the app session ID and bearer token, which are
// the values of the __Host-sp_app and __Host-sp_subject cookies.
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

	resp, err := post(LoginHost, "/webapi/login/finish", `{"id":"`+AliceCredID+`"}`, nil)
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

	resp, err = post(LoginHost, "/web/launch/"+app, "", session)
	if err != nil {
		return "", "", err
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || err != nil {
		return "", "", fmt.Errorf("launch: status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	parts := strings.Split(loc.Fragment, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("launch: fragment %q", loc.Fragment)
	}
	sid, bearer = parts[0], parts[1]

	body, _ := json.Marshal(map[string]string{"sid": sid, "subject": bearer})
	resp, err = post(app+"-"+LoginHost, "/x-teleport-auth", string(body), nil)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusNoContent {
		return "", "", fmt.Errorf("handoff: status %d", resp.StatusCode)
	}
	return sid, bearer, nil
}
