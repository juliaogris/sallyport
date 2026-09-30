//go:build js && wasm

package main

import (
	"cmp"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
// The other device opens the link, with no session, and its page uses the
// token as the invite page does:
//
//   - GET /web/add-passkey/<token> is the page.
//   - POST /webapi/add-passkey/<token>/begin returns WebAuthn creation
//     options for the token's user.
//   - POST /webapi/add-passkey/<token>/finish takes {"name": ...,
//     "credential": ...} and adds the passkey.
//
// A token that does not have auth's form is refused before auth is asked:
// 404 for the page, 403 "invalid token" for the POSTs, which is also
// auth's answer for a token it does not know or that has expired.

// clientStatus maps the gRPC codes of auth's client errors to HTTP:
// InvalidArgument, NotFound, AlreadyExists, PermissionDenied and
// Unauthenticated.
var clientStatus = map[string]int{"3": 400, "5": 404, "6": 409, "7": 403, "16": 401}

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

// proto encodes the assertion as an MFAAuthenticateResponse.
func (a *assertion) proto() (pb, error) {
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

// proto encodes the credential as a CredentialCreationResponse.
func (c *credential) proto() (pb, error) {
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
	existing, err := a.proto()
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
	cred, err := in.Credential.proto()
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
	existing, err := in.Assertion.proto()
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
// answer. Auth keeps the privilege token in the link until it expires, and
// a new link replaces it.
func (h *hub) passkeyLink(cert tls.Certificate, body []byte) *response {
	var a assertion
	if err := json.Unmarshal(body, &a); err != nil {
		return passkeyError("bad request", 400)
	}
	existing, err := a.proto()
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
	url := "https://" + h.cfg.loginHost() + "/web/add-passkey/" + token.id
	return jsonResponse(map[string]string{"url": url, "expires": token.expires.Format(time.RFC3339)})
}

// showAddPasskey serves the page for another device, or 404 for a token
// that does not have auth's form.
func (h *hub) showAddPasskey(token string) *response {
	if !validTokenID(token) {
		return textError("not found", 404)
	}
	return html(addPasskeyPage)
}

// addPasskeyAPI answers the /webapi/add-passkey routes. rest is the path
// after /webapi/add-passkey/, the token and the step.
func (h *hub) addPasskeyAPI(req *request, rest string) *response {
	token, step, ok := strings.Cut(rest, "/")
	if !ok || (step != "begin" && step != "finish") {
		return passkeyError("not found", 404)
	}
	if !validTokenID(token) {
		return passkeyError("invalid token", 403)
	}
	if step == "begin" {
		return h.addPasskeyBegin(token)
	}
	return h.addPasskeyFinish(token, req.body)
}

func (h *hub) addPasskeyBegin(token string) *response {
	resp, err := h.auth.call(createRegisterChallenge, createRegisterChallengeRequest(token))
	if err != nil {
		return authError(err)
	}
	v := registerChallenge(resp)
	if v == nil {
		return authError(errors.New("no WebAuthn creation options"))
	}
	return jsonResponse(v)
}

func (h *hub) addPasskeyFinish(token string, body []byte) *response {
	var in struct {
		Name       string     `json:"name"`
		Credential credential `json:"credential"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return passkeyError("bad request", 400)
	}
	cred, err := in.Credential.proto()
	if err != nil {
		return passkeyError("bad request", 400)
	}
	_, err = h.auth.call(addMFADeviceSync, addMFADeviceWithTokenRequest(token, in.Name, cred))
	if err != nil {
		return authError(err)
	}
	return jsonResponse(map[string]bool{"ok": true})
}

// authError answers a failed call to auth on a passkey route. A gRPC
// client error, one in [clientStatus], becomes the matching 4xx with
// auth's message as the body. These are the errors for a used name, a too
// long name, an unknown device and a bad or stale passkey answer, and auth
// writes their messages for the user. ResourceExhausted becomes 429, as on
// the login routes of the Rust hub. Every other error, including a
// transport error, is logged and answered with 502 "request failed".
func authError(err error) *response {
	var ge *grpcError
	if errors.As(err, &ge) {
		if ge.status == "8" {
			return passkeyError("too many requests, try again in a minute", 429)
		}
		if status, ok := clientStatus[ge.status]; ok {
			return passkeyError(cmp.Or(ge.message, "request refused"), status)
		}
	}
	logf("web: passkeys: %v", err)
	return passkeyError("request failed", 502)
}
