package main

import (
	"encoding/base64"
	"time"
)

// The auth request messages the hub sends and the response fields it
// reads, with the field numbers of Teleport's protos.

const (
	// scopePasswordlessLogin is teleport.mfa.v1.ChallengeScope for a
	// passwordless login.
	scopePasswordlessLogin = 2
	// scopeManageDevices is teleport.mfa.v1.ChallengeScope for adding and
	// removing devices.
	scopeManageDevices = 4
	// deviceTypeWebAuthn is proto.DeviceType for WebAuthn.
	deviceTypeWebAuthn = 3
	// deviceUsagePasswordless is proto.DeviceUsage for a passkey.
	deviceUsagePasswordless = 2
	// mfaDeviceWebAuthn is the webauthn field of a types.MFADevice.
	mfaDeviceWebAuthn = 10
)

// CreateAuthenticateChallengeRequest with passwordless set and the
// passwordless login scope.
func passwordlessChallengeRequest() []byte {
	return pb(nil).msg(4, nil).msg(6, pb(nil).int(1, scopePasswordlessLogin))
}

// manageDevicesChallengeRequest is a CreateAuthenticateChallengeRequest for
// the calling user with the manage devices scope.
func manageDevicesChallengeRequest() []byte {
	return pb(nil).msg(3, nil).msg(6, pb(nil).int(1, scopeManageDevices))
}

// getMFADevicesRequest lists the calling user's devices.
func getMFADevicesRequest() []byte { return pb(nil) }

// credentialAssertion is a webauthn.CredentialAssertionResponse, the
// browser's answer to an authenticate challenge.
func credentialAssertion(credType string, rawID, clientData, authData, signature, userHandle []byte) pb {
	resp := pb(nil).bytes(1, clientData).bytes(2, authData).bytes(3, signature).bytes(4, userHandle)
	return pb(nil).str(1, credType).bytes(2, rawID).msg(3, resp)
}

// mfaAuthenticateResponse wraps a CredentialAssertionResponse as an
// MFAAuthenticateResponse.
func mfaAuthenticateResponse(assertion pb) pb { return pb(nil).msg(3, assertion) }

// credentialCreation is a webauthn.CredentialCreationResponse, the
// browser's new credential.
func credentialCreation(credType string, rawID, clientData, attestation []byte) pb {
	att := pb(nil).bytes(1, clientData).bytes(2, attestation)
	return pb(nil).str(1, credType).bytes(2, rawID).msg(3, att)
}

// passkeyRegisterChallengeRequest is a CreateRegisterChallengeRequest for a
// new passkey of the calling user, confirmed with existing, an
// MFAAuthenticateResponse.
func passkeyRegisterChallengeRequest(existing pb) []byte {
	return pb(nil).int(2, deviceTypeWebAuthn).int(3, deviceUsagePasswordless).msg(4, existing)
}

// addMFADeviceSyncRequest adds cred, a CredentialCreationResponse, as a
// passkey called name for the calling user.
func addMFADeviceSyncRequest(name string, cred pb) []byte {
	return pb(nil).str(2, name).msg(3, pb(nil).msg(3, cred)).int(4, deviceUsagePasswordless).msg(5, nil)
}

// deleteMFADeviceSyncRequest removes the calling user's device called name,
// confirmed with existing, an MFAAuthenticateResponse.
func deleteMFADeviceSyncRequest(name string, existing pb) []byte {
	return pb(nil).str(2, name).msg(3, existing)
}

// passkey is what the passkeys page shows of a types.MFADevice.
type passkey struct {
	Name string `json:"name"`
	// AddedAt is RFC 3339 in UTC, to the second.
	AddedAt string `json:"addedAt"`
}

// passkeysOf reads the WebAuthn devices of a GetMFADevicesResponse. A
// device of another kind, such as TOTP, is left out.
func passkeysOf(resp fields) []passkey {
	list := []passkey{}
	for _, d := range resp.msgs(1) {
		if !d.has(mfaDeviceWebAuthn) {
			continue
		}
		added := time.Unix(d.msg(6).int(1), 0).UTC().Format(time.RFC3339)
		list = append(list, passkey{Name: d.msg(4).str(1), AddedAt: added})
	}
	return list
}

func getWebSessionRequest(user, sid string) []byte {
	return pb(nil).str(1, user).str(2, sid)
}

func createAppSessionRequest(user, publicAddr, cluster, app string) []byte {
	return pb(nil).str(1, user).str(3, publicAddr).str(4, cluster).str(9, app)
}

func getAppSessionRequest(sid string) []byte {
	return pb(nil).str(1, sid)
}

func createRegisterChallengeRequest(token string) []byte {
	return pb(nil).str(1, token).int(2, deviceTypeWebAuthn).int(3, deviceUsagePasswordless)
}

// changeUserAuthenticationRequest registers cred, a
// CredentialCreationResponse, as the passkey of an invite's user.
func changeUserAuthenticationRequest(token string, cred pb) []byte {
	return pb(nil).str(1, token).msg(3, pb(nil).msg(3, cred)).str(4, "passkey")
}

// webSession is the part of a types.WebSessionV2 the hub reads.
type webSession struct {
	name        string
	user        string
	privKey     []byte
	tlsCert     []byte
	bearerToken string
	expires     int64
	tlsPriv     []byte
}

// parseWebSession reads a WebSessionV2 message, or returns nil if m is
// nil or has no spec.
func parseWebSession(m fields) *webSession {
	if m == nil {
		return nil
	}
	spec := m.msg(5)
	if spec == nil && !m.has(5) {
		return nil
	}
	s := &webSession{name: m.msg(4).str(1)}
	if spec != nil {
		s.user = spec.str(1)
		s.privKey = spec.bytes(3)
		s.tlsCert = spec.bytes(4)
		s.bearerToken = spec.str(5)
		s.expires = spec.msg(7).int(1)
		s.tlsPriv = spec.bytes(15)
	}
	return s
}

// unexpired reports whether the session has an expiry and it has not
// passed.
func (s *webSession) unexpired() bool {
	return s.expires > time.Now().Unix()
}

// sessionOf reads the session of a GetAppSession, CreateAppSession or
// GetWebSession response.
func sessionOf(resp fields) *webSession { return parseWebSession(resp.msg(1)) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// loginChallenge turns an MFAAuthenticateChallenge into the JSON the login
// page reads, or nil if it has no WebAuthn challenge.
func loginChallenge(resp fields) map[string]any {
	o := resp.msg(3).msg(1)
	if o == nil {
		return nil
	}
	allow := []any{}
	for _, c := range o.msgs(4) {
		allow = append(allow, map[string]any{"type": c.str(1), "id": b64(c.bytes(2))})
	}
	return map[string]any{
		"challenge":        b64(o.bytes(1)),
		"rpId":             o.str(3),
		"timeout":          o.int(2),
		"userVerification": o.str(6),
		"allowCredentials": allow,
	}
}

// registerChallenge turns an MFARegisterChallenge into the JSON the invite
// page reads, or nil if it has no WebAuthn creation options.
func registerChallenge(resp fields) map[string]any {
	o := resp.msg(3).msg(1)
	if o == nil {
		return nil
	}
	rp, user, sel := o.msg(2), o.msg(3), o.msg(9)
	params := []any{}
	for _, p := range o.msgs(4) {
		params = append(params, map[string]any{"type": p.str(1), "alg": int32(p.int(2))})
	}
	exclude := []any{}
	for _, c := range o.msgs(6) {
		exclude = append(exclude, map[string]any{"type": c.str(1), "id": b64(c.bytes(2))})
	}
	requireRK := sel.int(2) != 0
	residentKey := "preferred"
	if requireRK {
		residentKey = "required"
	}
	selection := map[string]any{
		"requireResidentKey": requireRK,
		"residentKey":        residentKey,
		"userVerification":   sel.str(3),
	}
	if a := sel.str(1); a != "" {
		selection["authenticatorAttachment"] = a
	}
	return map[string]any{
		"challenge":              b64(o.bytes(1)),
		"rp":                     map[string]any{"id": rp.str(1), "name": rp.str(2)},
		"user":                   map[string]any{"id": b64(user.bytes(1)), "name": user.str(2), "displayName": user.str(3)},
		"pubKeyCredParams":       params,
		"timeout":                o.int(5),
		"excludeCredentials":     exclude,
		"attestation":            o.str(7),
		"authenticatorSelection": selection,
	}
}
