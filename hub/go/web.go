//go:build js && wasm

package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The browser side of the hub: invite, login, launcher and app hosts.
//
// Hosts are the login host and one host per app:
//
//   - <owner>.<domain> is the login host. It serves the invite page, the
//     passkey login and a dashboard with one launch link per app. Its
//     cookie is __Host-sp_session, the user and the web session ID.
//   - <app>-<owner>.<domain> is an app host. An app in SUB_APPS is at
//     <app>.<owner>.<domain> instead, under the login host, and is not
//     served at <app>-<owner>.<domain>. A launch starts on the app host,
//     which sets a state cookie and sends the browser to the launch on the
//     login host. The launch creates an app session and redirects to
//     /x-teleport-auth on the app host with the state in the query and the
//     session ID and its bearer token in the URL fragment. The page there
//     posts them back, and if the state matches the cookie, the hub sets
//     __Host-sp_app and __Host-sp_subject. Every other
//     request is checked with GetAppSession and forwarded to the app service
//     over the tunnel. An app session is valid only on the app host of its
//     certificate's app public address.
//
// Every POST must have an Origin equal to its own host. A launch is a GET,
// so that a launch link opens in a new tab, and is taken only from a page
// on the same site and only with a launch state.
const (
	sessionCookie = "__Host-sp_session"
	appCookie     = "__Host-sp_app"
	subjectCookie = "__Host-sp_subject"
	authPath      = "/x-teleport-auth"
	// stateCookiePrefix is the prefix of the state cookie of a launch, which
	// is followed by the ID part of the launch state.
	stateCookiePrefix = "__Host-sp_state_"
	// stateMaxAge is the lifetime of a state cookie in seconds.
	stateMaxAge = "60"
	// uiSessionCookie is the Teleport web UI's session cookie.
	uiSessionCookie = "__Host-session"
)

// uiCookieValue returns the value of the Teleport web UI's session cookie
// for the web session sid of user: the hex of a JSON object, as the proxy
// writes it.
func uiCookieValue(user, sid string) string {
	b, _ := json.Marshal(struct {
		User string `json:"user"`
		SID  string `json:"sid"`
	}{user, sid})
	return hex.EncodeToString(b)
}

// loginHostRequest answers a request for the login host.
func (h *hub) loginHostRequest(req *request) *response {
	host := h.cfg.loginHost()
	p := req.path
	if req.method == "POST" && !req.sameOrigin(host) {
		return textError("bad origin", 403)
	}
	var (
		v   map[string]any
		err error
	)
	switch {
	case req.method == "GET" && p == "/":
		return h.dashboard(req)
	case req.method == "GET" && p == "/web/login":
		return html(loginPage)
	case req.method == "POST" && p == "/webapi/login/begin":
		v, err = h.loginBegin()
	case req.method == "POST" && p == "/webapi/login/finish":
		return h.loginFinish(req.body)
	case req.method == "POST" && p == "/web/logout":
		return h.logout(req)
	case req.method == "GET" && strings.HasPrefix(p, "/web/invite/"):
		return html(invitePage)
	case req.method == "POST" && strings.HasPrefix(p, "/webapi/invite/"):
		token, step, ok := strings.Cut(strings.TrimPrefix(p, "/webapi/invite/"), "/")
		switch {
		case !ok:
			return textError("not found", 404)
		case step == "begin":
			v, err = h.registerChallengeFor(token)
		case step == "finish":
			return h.inviteFinish(token, req.body)
		default:
			return textError("not found", 404)
		}
	case req.method == "GET" && strings.HasPrefix(p, "/web/launch/"):
		return h.launch(req, strings.TrimPrefix(p, "/web/launch/"))
	case req.method == "GET" && p == "/web/passkeys":
		return h.showPasskeys(req)
	case p == "/webapi/passkeys" || strings.HasPrefix(p, "/webapi/passkeys/"):
		return h.passkeyAPI(req, strings.TrimPrefix(strings.TrimPrefix(p, "/webapi/passkeys"), "/"))
	case req.method == "GET" && p == "/web/add-passkey":
		return html(addPasskeyPage)
	case req.method == "POST" && p == "/webapi/add-passkey/begin":
		return h.addPasskeyBegin(req.body)
	case req.method == "POST" && p == "/webapi/add-passkey/finish":
		return h.addPasskeyFinish(req.body)
	default:
		return textError("not found", 404)
	}
	if err != nil {
		logf("web: %v", err)
		if rateLimited(err) {
			return textError(rateLimitedMsg, 429)
		}
		if errors.Is(err, errDialRefused) {
			return textError("auth unavailable", 503)
		}
		return textError("request failed", 502)
	}
	return jsonResponse(v)
}

// toLogin sends the browser to the login host and clears the app cookies.
func (h *hub) toLogin() *response {
	return redirect("https://"+h.cfg.loginHost()+"/").
		add("set-cookie", expireCookie(appCookie)).
		add("set-cookie", expireCookie(subjectCookie))
}

// appHostRequest answers a request for an app host.
func (h *hub) appHostRequest(req *request, app string) *response {
	host := req.host
	switch {
	case req.path == authPath:
		switch req.method {
		case "GET":
			if _, ok := req.queryValue("state"); ok {
				return html(handoffPage)
			}
			return h.startLaunch(app)
		case "POST":
			if !req.sameOrigin(host) {
				return textError("bad origin", 403)
			}
			return h.handoff(req)
		default:
			return textError("method not allowed", 405)
		}
	case req.path == "/teleport-logout":
		return h.toLogin()
	case req.method == "GET" && req.path == "/web/login" && h.cfg.webUIApps[app]:
		// The web UI's logout deletes the web session, and auth deletes
		// the app session with it, so the UI's own login page could not
		// reach the UI. The login is on the login host.
		return h.toLogin()
	case strings.HasPrefix(req.path, "/x-teleport-dbsc"):
		return textError("not found", 404)
	}
	// Every app host is the same site, so SameSite=Lax still sends the app
	// cookies on a POST from a sibling app host. Only this host may send a
	// request that can change state.
	// A WebSocket handshake is a GET, but it opens a connection that can
	// change state, so it gets the same check.
	switch {
	case req.method == "GET" && !req.isUpgrade(), req.method == "HEAD", req.method == "OPTIONS":
	default:
		if !req.sameOriginFetch(host) {
			return textError("bad origin", 403)
		}
	}
	sid, ok1 := req.cookie(appCookie)
	subject, ok2 := req.cookie(subjectCookie)
	if !ok1 || !ok2 {
		return h.toLogin()
	}
	// Auth is asked on every request, and any error denies.
	resp, err := h.auth.call(getAppSession, getAppSessionRequest(sid))
	if err != nil {
		if notFound(err) {
			return h.toLogin()
		}
		logf("web: GetAppSession for %s: %v", app, err)
		return textError("auth unavailable", 503)
	}
	s := sessionOf(resp)
	if s == nil || !s.unexpired() || !ctEq(s.bearerToken, subject) || !certForHost(s.tlsCert, host) {
		return h.toLogin()
	}
	if h.lazy != nil {
		if !h.lazy.connected() {
			logf("web: %s: app service offline, auth is not connected", app)
			return textError("app service offline", 503)
		}
	} else {
		h.appMu.Lock()
		t := h.appTunnel
		h.appMu.Unlock()
		if t == nil {
			logf("web: %s: app service offline, no tunnel", app)
			return textError("app service offline", 503)
		}
	}
	cert, err := h.userCert(s.tlsCert, s.tlsPriv)
	if err != nil {
		return textError(err.Error(), 500)
	}
	if req.isUpgrade() {
		return h.forwardWS(cert, host, req)
	}
	return h.forward(sid, cert, host, req)
}

// startLaunch sets a state cookie for a launch of app and sends the
// browser to the launch on the login host with the state. The handoff
// takes only a state whose cookie this browser has, so a handoff link made
// by another browser does not sign this one in.
func (h *hub) startLaunch(app string) *response {
	state, secret, id := newState()
	return redirect("https://"+h.cfg.loginHost()+"/web/launch/"+app+"?state="+state).
		add("set-cookie", setCookie(stateCookiePrefix+id, secret)+"; Max-Age="+stateMaxAge).
		add("referrer-policy", "no-referrer")
}

// handoff checks the handoff from the launcher for an app session of the
// request's host and its launch state, clears the state cookie, and sets
// the app cookies. For an app in WEB_UI_APPS it also sets the web UI's
// session cookie.
func (h *hub) handoff(req *request) *response {
	host := req.host
	var in struct {
		Sid     string `json:"sid"`
		Subject string `json:"subject"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(req.body, &in); err != nil {
		return textError("bad handoff", 400)
	}
	if in.Sid == "" || in.Subject == "" {
		return textError("bad handoff", 400)
	}
	secret, id, ok := parseState(in.State)
	if !ok {
		return textError("bad handoff", 403)
	}
	if c, ok := req.cookie(stateCookiePrefix + id); !ok || !ctEq(c, secret) {
		return textError("bad handoff", 403)
	}
	resp, err := h.auth.call(getAppSession, getAppSessionRequest(in.Sid))
	if err != nil {
		if notFound(err) {
			return textError("bad handoff", 403)
		}
		logf("web: handoff GetAppSession: %v", err)
		return textError("auth unavailable", 503)
	}
	s := sessionOf(resp)
	if s == nil || !s.unexpired() || !ctEq(s.bearerToken, in.Subject) || !certForHost(s.tlsCert, host) {
		return textError("bad handoff", 403)
	}
	result := (&response{status: 204}).
		add("set-cookie", expireCookie(stateCookiePrefix+id)).
		add("set-cookie", setCookie(appCookie, in.Sid)).
		add("set-cookie", setCookie(subjectCookie, in.Subject))
	if ui, ok := h.ui.take(in.Sid, time.Now()); ok {
		h.addUISession(result, ui)
	}
	return result
}

// addUISession adds the Teleport web UI's session cookie for ui to resp, if
// auth still has the web session and it has not expired. The cookie lives
// as long as the session.
func (h *hub) addUISession(resp *response, ui uiSession) {
	got, err := h.auth.call(getWebSession, getWebSessionRequest(ui.user, ui.sid))
	if err != nil {
		if !notFound(err) {
			logf("web: handoff GetWebSession: %v", err)
		}
		return
	}
	s := sessionOf(got)
	if s == nil || !s.unexpired() {
		return
	}
	left := strconv.FormatInt(s.expires-time.Now().Unix(), 10)
	resp.add("set-cookie", setCookie(uiSessionCookie, uiCookieValue(ui.user, ui.sid))+"; Max-Age="+left)
}

// webSession returns the logged-in user and the web session, if the
// session cookie names a web session that auth has and that has not
// expired. The error is the failed call to auth, when the session is nil
// because of one.
func (h *hub) webSession(req *request) (string, *webSession, error) {
	value, ok := req.cookie(sessionCookie)
	if !ok {
		return "", nil, nil
	}
	user, sid, ok := strings.Cut(value, ":")
	if !ok {
		return "", nil, nil
	}
	resp, err := h.auth.call(getWebSession, getWebSessionRequest(user, sid))
	if err != nil {
		logf("web: GetWebSession: %v", err)
		return "", nil, err
	}
	s := sessionOf(resp)
	if s == nil || !s.unexpired() {
		return "", nil, nil
	}
	return user, s, nil
}

// logout deletes the user's app sessions and the web session at auth, as
// the user, and expires the session cookie. The cookie is expired even if
// a delete fails.
func (h *hub) logout(req *request) *response {
	resp := redirect("/web/login").add("set-cookie", expireCookie(sessionCookie))
	user, s, _ := h.webSession(req)
	if s == nil {
		return resp
	}
	cert, err := h.sessionCert(s)
	if err != nil {
		logf("web: logout: %v", err)
		return resp
	}
	if _, err := h.callAs(cert, deleteUserAppSessions, deleteUserAppSessionsRequest(user)); err != nil {
		logf("web: logout: DeleteUserAppSessions: %v", err)
	}
	if _, err := h.callAs(cert, deleteWebSession, deleteWebSessionRequest(user, s.name)); err != nil && !notFound(err) {
		logf("web: logout: DeleteWebSession: %v", err)
	}
	return resp
}

func (h *hub) dashboard(req *request) *response {
	user, s, _ := h.webSession(req)
	if s == nil {
		return redirect("/web/login")
	}
	var b strings.Builder
	for _, a := range h.cfg.apps {
		fmt.Fprintf(&b, `<div><a class="app" href="/web/launch/%s">%s</a></div>`, a.name, a.name)
	}
	return html(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">` + style + `<title>sallyport</title>
<p>Logged in as ` + user + `.</p>` + b.String() + `<p><a href="/web/passkeys">Passkeys</a></p><form method="post" action="/web/logout"><button>Log out</button></form>`)
}

func (h *hub) launch(req *request, name string) *response {
	start := ""
	for _, a := range h.cfg.apps {
		if a.name == name {
			start = a.start
		}
	}
	if start == "" {
		return textError("not found", 404)
	}
	state, ok := req.queryValue("state")
	// Without a state the launch did not start on the app host, which is
	// where the state cookie must be set, so send the browser there first.
	if !ok {
		return redirect("https://" + h.cfg.appHost(name) + authPath)
	}
	if _, _, ok := parseState(state); !ok {
		return textError("bad launch", 400)
	}
	if !req.fromSameSite() {
		return textError("bad origin", 403)
	}
	user, s, _ := h.webSession(req)
	if s == nil {
		return redirect("/web/login")
	}
	publicAddr := h.cfg.appHost(name)
	sid, bearer, err := func() (string, string, error) {
		cert, err := h.sessionCert(s)
		if err != nil {
			return "", "", err
		}
		created, err := h.callAs(cert, createAppSession, createAppSessionRequest(user, publicAddr, h.cfg.cluster, name))
		if err != nil {
			return "", "", err
		}
		sid := created.msg(1).msg(4).str(1)
		if sid == "" {
			return "", "", errors.New("no app session name")
		}
		got, err := h.auth.call(getAppSession, getAppSessionRequest(sid))
		if err != nil {
			return "", "", err
		}
		gs := sessionOf(got)
		if gs == nil || gs.bearerToken == "" {
			return "", "", errors.New("no bearer token")
		}
		return sid, gs.bearerToken, nil
	}()
	if err != nil {
		logf("web: launch %s: %v", name, err)
		if errors.Is(err, errDialRefused) {
			return textError("auth unavailable", 503)
		}
		return textError("launch failed", 502)
	}
	if h.cfg.webUIApps[name] {
		h.ui.put(sid, user, s.name, time.Now())
	}
	return (&response{status: 303}).
		add("location", "https://"+publicAddr+authPath+"?state="+state+"#"+sid+"."+bearer+"."+b64([]byte(start))).
		add("referrer-policy", "no-referrer")
}

func (h *hub) loginBegin() (map[string]any, error) {
	resp, err := h.auth.call(createAuthenticateChallenge, passwordlessChallengeRequest())
	if err != nil {
		return nil, err
	}
	v := loginChallenge(resp)
	if v == nil {
		return nil, errors.New("no WebAuthn challenge")
	}
	return v, nil
}

func (h *hub) loginFinish(assertion []byte) *response {
	user, sid, err := func() (string, string, error) {
		var a json.RawMessage
		if err := json.Unmarshal(assertion, &a); err != nil {
			return "", "", fmt.Errorf("assertion: %w", err)
		}
		// A call to auth takes a stream, or a dial in the lazy hub, so a
		// body that is not an assertion is refused before one is taken.
		if err := checkAssertion(a, h.cfg.loginOrigin()); err != nil {
			return "", "", err
		}
		if err := h.cfg.err("HUB_TLS_CERT", "HUB_TLS_KEY"); err != nil {
			return "", "", err
		}
		body, _ := json.Marshal(map[string]any{"username": "", "webauthn": a})
		status, out, err := h.postJSON(*h.cfg.tlsCert, authenticateWebUserPasswordless, body)
		if err != nil {
			return "", "", err
		}
		if status != 200 {
			return "", "", fmt.Errorf("AuthenticateWebUser: http %d: %s", status, out)
		}
		var web struct {
			Metadata struct {
				Name *string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				User *string `json:"user"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(out, &web); err != nil {
			return "", "", fmt.Errorf("web session: %w", err)
		}
		if web.Metadata.Name == nil {
			return "", "", errors.New("no web session name")
		}
		if web.Spec.User == nil {
			return "", "", errors.New("no web session user")
		}
		return *web.Spec.User, *web.Metadata.Name, nil
	}()
	return sessionResponse(user, sid, err)
}

// registerChallengeFor asks auth for WebAuthn creation options for the user
// of token, an invite or a privilege token, as the pages read them.
func (h *hub) registerChallengeFor(token string) (map[string]any, error) {
	resp, err := h.auth.call(createRegisterChallenge, createRegisterChallengeRequest(token))
	if err != nil {
		return nil, err
	}
	v := registerChallenge(resp)
	if v == nil {
		return nil, errors.New("no WebAuthn creation options")
	}
	return v, nil
}

func (h *hub) inviteFinish(token string, body []byte) *response {
	user, sid, err := func() (string, string, error) {
		var c credential
		if err := json.Unmarshal(body, &c); err != nil {
			return "", "", fmt.Errorf("credential: %w", err)
		}
		cred, err := c.proto(h.cfg.loginOrigin())
		if err != nil {
			return "", "", fmt.Errorf("credential: %w", err)
		}
		resp, err := h.auth.call(changeUserAuthentication, changeUserAuthenticationRequest(token, cred))
		if err != nil {
			return "", "", err
		}
		ws := resp.msg(1)
		if ws == nil {
			return "", "", errors.New("no web session")
		}
		if !ws.has(4) {
			return "", "", errors.New("no web session name")
		}
		if !ws.has(5) {
			return "", "", errors.New("no web session user")
		}
		return ws.msg(5).str(1), ws.msg(4).str(1), nil
	}()
	return sessionResponse(user, sid, err)
}

// sessionResponse sets the session cookie for a new web session, or
// reports the failure.
func sessionResponse(user, sid string, err error) *response {
	if errors.Is(err, errDialRefused) {
		logf("web: %v", err)
		return textError("auth unavailable", 503)
	}
	if err != nil {
		logf("web: %v", err)
		return textError("login failed", 401)
	}
	logf("web: web session for %q", user)
	return jsonResponse(map[string]bool{"ok": true}).add("set-cookie", setCookie(sessionCookie, user+":"+sid))
}

// sessionCert returns the web session's user certificate, for calls to
// auth as the user. Auth sets tlsPriv only when it issues separate SSH and
// TLS keys. Otherwise privKey is both.
func (h *hub) sessionCert(s *webSession) (tls.Certificate, error) {
	key := s.tlsPriv
	if len(key) == 0 {
		key = s.privKey
	}
	return h.userCert(s.tlsCert, key)
}

// userCert parses a user's PEM certificate and key from auth.
func (h *hub) userCert(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("user identity: %w", err)
	}
	return cert, nil
}
