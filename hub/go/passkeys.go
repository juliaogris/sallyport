//go:build js && wasm

package main

import (
	"cmp"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Passkey management on the login host, for the logged-in user. Every call
// to auth is made as the user, with the web session's certificate.
//
//   - GET /web/passkeys is the page. Without a session it redirects to
//     /web/login.
//   - GET /webapi/passkeys lists the user's devices as
//     {"passkeys": [{"name": ..., "addedAt": ...}]}.
//   - POST /webapi/passkeys/challenge creates an authenticate challenge
//     with the manage devices scope and returns WebAuthn request options,
//     as /webapi/login/begin does.
//   - POST /webapi/passkeys/begin takes the browser's answer to that
//     challenge and returns WebAuthn creation options, as an invite's
//     begin does.
//   - POST /webapi/passkeys/finish takes {"name": ..., "credential": ...}
//     and adds the passkey.
//   - POST /webapi/passkeys/delete takes {"name": ..., "assertion": ...},
//     a fresh answer to a challenge, and removes the passkey. The last
//     passkey is not removed: 409 "cannot remove the last passkey".
//   - POST /webapi/passkeys/link takes a fresh answer to a challenge and
//     returns {"url": ..., "expires": ...}, a link for another device with
//     a privilege token, and when the token expires in RFC 3339.
//
// The JSON routes answer 401 "not logged in" without a valid session, 503
// "auth unavailable" when auth could not be asked for the session, and
// {"ok": true} when a finish or delete worked. Errors from auth are mapped
// by [authError].
//
// The other device opens the link, with no session. The token is in the
// URL fragment, so it reaches neither a request log nor a Referer, and the
// page takes it out of the address bar and sends it in the body of each
// POST:
//
//   - GET /web/add-passkey is the page.
//   - POST /webapi/add-passkey/begin takes {"token": ...} and returns
//     WebAuthn creation options for the token's user.
//   - POST /webapi/add-passkey/finish takes {"token": ..., "name": ...,
//     "credential": ...} and adds the passkey.
//
// A token that does not have auth's form is refused before auth is asked:
// 403 "invalid token", which is also auth's answer for a token it does not
// know or that has expired.
//
// A token adds one passkey. Auth keeps a privilege token until it expires,
// so the hub records the ID of a token whose finish added a passkey, in
// Durable Object storage, and answers 403 "invalid token" for it on begin
// and finish from then on. A finish that auth refused does not use the
// token up.

// clientStatus maps the gRPC codes of auth's client errors to HTTP:
// InvalidArgument, NotFound, AlreadyExists, PermissionDenied and
// Unauthenticated.
var clientStatus = map[string]int{"3": 400, "5": 404, "6": 409, "7": 403, "16": 401}

// privilegeTokenTTL is how long auth keeps a privilege token.
const privilegeTokenTTL = 5 * time.Minute

// passkeyHandler answers one /webapi/passkeys route as the user of cert,
// with the request body.
type passkeyHandler func(cert tls.Certificate, body []byte) *response

// passkeyError is an error on a passkey route: msg as plain text that the
// browser must not sniff, because auth's messages can hold a device name.
func passkeyError(msg string, status int) *response {
	return textError(msg, status).add("content-type", "text/plain; charset=utf-8").add("x-content-type-options", "nosniff")
}

// assertion is the browser's answer to an authenticate challenge, as the
// pages send it.
type assertion struct {
	Type     string `json:"type"`
	RawID    string `json:"rawId"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

// proto encodes the assertion as an MFAAuthenticateResponse. It returns an
// error unless the assertion is from a page at origin.
func (a *assertion) proto(origin string) (pb, error) {
	if err := checkClientData(a.Response.ClientDataJSON, "webauthn.get", origin); err != nil {
		return nil, err
	}
	b, err := decodeAll(a.RawID, a.Response.ClientDataJSON, a.Response.AuthenticatorData, a.Response.Signature, a.Response.UserHandle)
	if err != nil {
		return nil, err
	}
	cred := credentialAssertion(cmp.Or(a.Type, "public-key"), b[0], b[1], b[2], b[3], b[4])
	return mfaAuthenticateResponse(cred), nil
}

// credential is the browser's new credential, as the pages send it.
type credential struct {
	Type     string `json:"type"`
	RawID    string `json:"rawId"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
}

// proto encodes the credential as a CredentialCreationResponse. It returns
// an error unless the credential is from a page at origin.
func (c *credential) proto(origin string) (pb, error) {
	if err := checkClientData(c.Response.ClientDataJSON, "webauthn.create", origin); err != nil {
		return nil, err
	}
	b, err := decodeAll(c.RawID, c.Response.ClientDataJSON, c.Response.AttestationObject)
	if err != nil {
		return nil, err
	}
	return credentialCreation(cmp.Or(c.Type, "public-key"), b[0], b[1], b[2]), nil
}

// decodeAll decodes base64url values without padding, as the pages encode
// bytes.
func decodeAll(values ...string) ([][]byte, error) {
	decoded := make([][]byte, len(values))
	for i, v := range values {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("base64: %w", err)
		}
		decoded[i] = b
	}
	return decoded, nil
}

// showPasskeys serves the passkeys page, or sends the browser to log in.
func (h *hub) showPasskeys(req *request) *response {
	if _, s, _ := h.webSession(req); s == nil {
		return redirect("/web/login")
	}
	return html(passkeysPage)
}

// passkeyAPI answers the /webapi/passkeys routes. action is the path after
// /webapi/passkeys/, or "" for the list.
func (h *hub) passkeyAPI(req *request, action string) *response {
	handle := h.passkeyRoute(req.method, action)
	if handle == nil {
		return passkeyError("not found", 404)
	}
	_, s, err := h.webSession(req)
	if err != nil && !notFound(err) {
		return passkeyError("auth unavailable", 503)
	}
	if s == nil {
		return passkeyError("not logged in", 401)
	}
	cert, err := h.sessionCert(s)
	if err != nil {
		return passkeyError(err.Error(), 500)
	}
	return handle(cert, req.body)
}

// notFound reports whether err is auth's NotFound.
func notFound(err error) bool {
	var ge *grpcError
	return errors.As(err, &ge) && ge.status == "5"
}

// passkeyRoute returns the handler of a /webapi/passkeys route, or nil for
// a method and action that is no route.
func (h *hub) passkeyRoute(method, action string) passkeyHandler {
	switch {
	case method == "GET" && action == "":
		return h.listPasskeys
	case method != "POST":
		return nil
	case action == "challenge":
		return h.passkeyChallenge
	case action == "begin":
		return h.passkeyBegin
	case action == "finish":
		return h.passkeyFinish
	case action == "delete":
		return h.passkeyDelete
	case action == "link":
		return h.passkeyLink
	}
	return nil
}

func (h *hub) listPasskeys(cert tls.Certificate, _ []byte) *response {
	resp, err := h.callAs(cert, getMFADevices, getMFADevicesRequest())
	if err != nil {
		return authError(err)
	}
	return jsonResponse(map[string]any{"passkeys": passkeysOf(resp)})
}

func (h *hub) passkeyChallenge(cert tls.Certificate, _ []byte) *response {
	resp, err := h.callAs(cert, createAuthenticateChallenge, manageDevicesChallengeRequest())
	if err != nil {
		return authError(err)
	}
	v := loginChallenge(resp)
	if v == nil {
		return authError(errors.New("no WebAuthn challenge"))
	}
	return jsonResponse(v)
}

func (h *hub) passkeyBegin(cert tls.Certificate, body []byte) *response {
	var a assertion
	if err := json.Unmarshal(body, &a); err != nil {
		return passkeyError("bad request", 400)
	}
	existing, err := a.proto(h.cfg.loginOrigin())
	if err != nil {
		return passkeyError("bad request", 400)
	}
	resp, err := h.callAs(cert, createRegisterChallenge, passkeyRegisterChallengeRequest(existing))
	if err != nil {
		return authError(err)
	}
	v := registerChallenge(resp)
	if v == nil {
		return authError(errors.New("no WebAuthn creation options"))
	}
	return jsonResponse(v)
}

func (h *hub) passkeyFinish(cert tls.Certificate, body []byte) *response {
	var in struct {
		Name       string     `json:"name"`
		Credential credential `json:"credential"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return passkeyError("bad request", 400)
	}
	cred, err := in.Credential.proto(h.cfg.loginOrigin())
	if err != nil {
		return passkeyError("bad request", 400)
	}
	_, err = h.callAs(cert, addMFADeviceSync, addMFADeviceSyncRequest(in.Name, cred))
	if err != nil {
		return authError(err)
	}
	return jsonResponse(map[string]bool{"ok": true})
}

// passkeyDelete removes a passkey after a fresh challenge answer. It lists
// the user's passkeys first and refuses to remove the last one, before the
// answer reaches auth. Auth allows that when the user has a password, and
// the hub has no password login.
func (h *hub) passkeyDelete(cert tls.Certificate, body []byte) *response {
	var in struct {
		Name      string    `json:"name"`
		Assertion assertion `json:"assertion"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return passkeyError("bad request", 400)
	}
	existing, err := in.Assertion.proto(h.cfg.loginOrigin())
	if err != nil {
		return passkeyError("bad request", 400)
	}
	devices, err := h.callAs(cert, getMFADevices, getMFADevicesRequest())
	if err != nil {
		return authError(err)
	}
	if len(passkeysOf(devices)) <= 1 {
		return passkeyError("cannot remove the last passkey", 409)
	}
	_, err = h.callAs(cert, deleteMFADeviceSync, deleteMFADeviceSyncRequest(in.Name, existing))
	if err != nil {
		return authError(err)
	}
	return jsonResponse(map[string]bool{"ok": true})
}

// passkeyLink makes a link for another device after a fresh challenge
// answer. The privilege token in the link adds one passkey. It expires
// after privilegeTokenTTL, and a new link replaces it.
func (h *hub) passkeyLink(cert tls.Certificate, body []byte) *response {
	var a assertion
	if err := json.Unmarshal(body, &a); err != nil {
		return passkeyError("bad request", 400)
	}
	existing, err := a.proto(h.cfg.loginOrigin())
	if err != nil {
		return passkeyError("bad request", 400)
	}
	resp, err := h.callAs(cert, createPrivilegeToken, createPrivilegeTokenRequest(existing))
	if err != nil {
		return authError(err)
	}
	token := privilegeTokenOf(resp)
	if token == nil {
		return authError(errors.New("no privilege token"))
	}
	url := "https://" + h.cfg.loginHost() + "/web/add-passkey#" + token.id
	return jsonResponse(map[string]string{"url": url, "expires": token.expires.Format(time.RFC3339)})
}

// addPasskeyRequest is the body of the add-passkey routes. A begin has only
// the token.
type addPasskeyRequest struct {
	Token      string     `json:"token"`
	Name       string     `json:"name"`
	Credential credential `json:"credential"`
}

// parse reads body into the request. It answers 400 for a body that is not
// JSON and 403 for a token that does not have auth's form, or nil.
func (in *addPasskeyRequest) parse(body []byte) *response {
	if err := json.Unmarshal(body, in); err != nil {
		return passkeyError("bad request", 400)
	}
	if !validTokenID(in.Token) {
		return passkeyError("invalid token", 403)
	}
	return nil
}

// addPasskeyBegin returns WebAuthn creation options for the user of the
// token in body.
func (h *hub) addPasskeyBegin(body []byte) *response {
	var in addPasskeyRequest
	if refused := in.parse(body); refused != nil {
		return refused
	}
	if tokenUsed(in.Token) {
		return passkeyError("invalid token", 403)
	}
	v, err := h.registerChallengeFor(in.Token)
	if err != nil {
		return authError(err)
	}
	return jsonResponse(v)
}

// addPasskeyFinish adds the credential in body as a passkey of the user of
// the token in body, and uses the token up.
func (h *hub) addPasskeyFinish(body []byte) *response {
	var in addPasskeyRequest
	if refused := in.parse(body); refused != nil {
		return refused
	}
	cred, err := in.Credential.proto(h.cfg.loginOrigin())
	if err != nil {
		return passkeyError("bad request", 400)
	}
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()
	if tokenUsed(in.Token) {
		return passkeyError("invalid token", 403)
	}
	_, err = h.auth.call(addMFADeviceSync, addMFADeviceWithTokenRequest(in.Token, in.Name, cred))
	if err != nil {
		return authError(err)
	}
	useToken(in.Token)
	return jsonResponse(map[string]bool{"ok": true})
}

// tokenUsed reports whether the privilege token id has added a passkey.
func tokenUsed(id string) bool {
	return glue.tokenUsed.Invoke(id).Bool()
}

// useToken records in Durable Object storage that the privilege token id
// added a passkey. The record is kept for privilegeTokenTTL, by when auth
// has expired the token, and dropped after that.
func useToken(id string) {
	now := time.Now()
	glue.tokenUse.Invoke(id, now.UnixMilli(), now.Add(privilegeTokenTTL).UnixMilli())
}

// authError answers a failed call to auth on a passkey route. A gRPC
// client error, one in [clientStatus], becomes the matching 4xx with
// auth's message as the body. These are the errors for a used name, a too
// long name, an unknown device and a bad or stale passkey answer, and auth
// writes their messages for the user. ResourceExhausted becomes 429, as on
// the login routes. A stream that auth's callout refused becomes 503 "auth
// unavailable". Every other error, including a transport error, is logged
// and answered with 502 "request failed".
func authError(err error) *response {
	if rateLimited(err) {
		return passkeyError(rateLimitedMsg, 429)
	}
	if errors.Is(err, errDialRefused) {
		logf("web: passkeys: %v", err)
		return passkeyError("auth unavailable", 503)
	}
	var ge *grpcError
	if errors.As(err, &ge) {
		if status, ok := clientStatus[ge.status]; ok {
			return passkeyError(cmp.Or(ge.message, "request refused"), status)
		}
	}
	logf("web: passkeys: %v", err)
	return passkeyError("request failed", 502)
}
