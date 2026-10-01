package conformance

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protowire"
)

// The test users. Alice has a passkey called AliceDevice. Bob has an
// invite.
const (
	Alice       = "alice"
	AliceCredID = "cred-alice"
	AliceDevice = "passkey"
	Bob         = "bob"
	BobInvite   = "tok-bob"
	BobCredID   = "cred-bob"
	RPID        = LoginHost
)

// AliceDeviceAdded is when Alice's passkey was added.
var AliceDeviceAdded = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// PrivilegeTokenTTL is how long a privilege token lives, as in auth.
const PrivilegeTokenTTL = 5 * time.Minute

// Device is one MFA device of a user. Every device is a passkey.
type Device struct {
	Name    string
	CredID  string
	AddedAt time.Time
}

// userToken is a privilege token: who it is for and when it expires.
type userToken struct {
	user    string
	expires time.Time
}

// FakeAuth stands in for Teleport's auth service behind the callout. It
// keeps callout streams open to a hub and answers the calls the hub makes
// on them: unary gRPC on h2, and the passwordless login on the legacy HTTP
// API.
type FakeAuth struct {
	pki *PKI
	srv *http.Server
	ln  *connListener

	mu      sync.Mutex
	web     map[string]*session
	app     map[string]*session
	calls   []Call
	sockets map[*websocket.Conn]bool
	// devices are each user's MFA devices.
	devices map[string][]Device
	// manageChallenges are the manage-devices challenges issued and not
	// yet answered, each with its user. An answer uses one up.
	manageChallenges map[string]string
	// registering are the users with a register challenge issued and not
	// yet finished. A finish needs one and uses it up.
	registering map[string]struct{}
	// tokens are the privilege tokens by ID. A user has at most one.
	tokens map[string]*userToken
	// LoginChallenge is the challenge in every login challenge.
	LoginChallenge []byte
	// RegisterChallenge is the challenge in every register challenge.
	RegisterChallenge []byte
	// rateLimited makes the challenge calls fail with ResourceExhausted.
	rateLimited bool
}

// Devices returns user's MFA devices.
func (a *FakeAuth) Devices(user string) []Device {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Device(nil), a.devices[user]...)
}

// SetRateLimited makes CreateAuthenticateChallenge and
// CreateRegisterChallenge fail with ResourceExhausted while on is true, as
// auth does when its rate limit is reached.
func (a *FakeAuth) SetRateLimited(on bool) {
	a.mu.Lock()
	a.rateLimited = on
	a.mu.Unlock()
}

// DropStreams closes every callout stream open now, waiting or in use.
// Run opens new ones.
func (a *FakeAuth) DropStreams() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for ws := range a.sockets {
		ws.Close()
		delete(a.sockets, ws)
	}
}

// Call is one call the hub made to FakeAuth.
type Call struct {
	Path string
	// Client is the common name of the hub's client certificate, or "".
	Client string
}

type session struct {
	name, user, bearer string
	expires            time.Time
	certPEM, keyPEM    []byte
}

// NewFakeAuth returns a FakeAuth for the cluster in p.
func NewFakeAuth(p *PKI) (*FakeAuth, error) {
	cert, err := p.TLSLeaf("auth", authSNI)
	if err != nil {
		return nil, err
	}
	a := &FakeAuth{
		pki:               p,
		ln:                newConnListener(),
		web:               make(map[string]*session),
		app:               make(map[string]*session),
		sockets:           make(map[*websocket.Conn]bool),
		devices:           map[string][]Device{Alice: {{Name: AliceDevice, CredID: AliceCredID, AddedAt: AliceDeviceAdded}}},
		manageChallenges:  map[string]string{},
		registering:       map[string]struct{}{},
		tokens:            map[string]*userToken{},
		LoginChallenge:    randomBytes(32),
		RegisterChallenge: randomBytes(32),
	}
	// ServeMux would clean the empty segment out of the legacy login path,
	// so the paths are matched here.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, isGRPC := strings.CutPrefix(r.URL.Path, "/proto.AuthService/")
		switch {
		case r.Method != "POST":
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		case isGRPC:
			a.grpc(w, r, method)
		case r.URL.Path == "/v2/users//web/authenticate":
			a.authenticateWebUser(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	a.srv = &http.Server{Handler: handler}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    p.TLSCAPool,
	}
	go a.srv.Serve(tls.NewListener(a.ln, tlsCfg))
	return a, nil
}

// authSNI is the name auth's certificate is checked against.
const authSNI = "teleport.cluster.local"

// Run keeps n callout streams open to h until ctx ends. When the hub
// starts to use a stream, Run serves auth on it and opens another.
func (a *FakeAuth) Run(ctx context.Context, h *Hub, n int) {
	for range n {
		go func() {
			for ctx.Err() == nil {
				if err := a.serveOne(ctx, h); err != nil && ctx.Err() == nil {
					time.Sleep(200 * time.Millisecond)
				}
			}
		}()
	}
}

func (a *FakeAuth) serveOne(ctx context.Context, h *Hub) error {
	ws, err := h.DialCallout(ctx, a.pki, CalloutOpts{})
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.sockets[ws] = true
	a.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { ws.Close() })
	defer stop()
	_, first, err := ws.ReadMessage()
	if err != nil {
		a.drop(ws)
		ws.Close()
		return err
	}
	if !a.ln.put(&prefixConn{Conn: NewWSConn(ws), prefix: first}) {
		ws.Close()
	}
	return nil
}

func (a *FakeAuth) drop(ws *websocket.Conn) {
	a.mu.Lock()
	delete(a.sockets, ws)
	a.mu.Unlock()
}

// Close stops serving and closes every callout stream.
func (a *FakeAuth) Close() {
	a.srv.Close()
	a.ln.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	for ws := range a.sockets {
		ws.Close()
	}
}

// Calls returns the calls the hub made so far.
func (a *FakeAuth) Calls() []Call {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Call(nil), a.calls...)
}

// ExpireWebSessions makes every web session expired.
func (a *FakeAuth) ExpireWebSessions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.web {
		s.expires = time.Now().Add(-time.Minute)
	}
}

// ExpireUserTokens makes every privilege token expired.
func (a *FakeAuth) ExpireUserTokens() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tokens {
		t.expires = time.Now().Add(-time.Minute)
	}
}

// ExpireAppSessions makes every app session expired.
func (a *FakeAuth) ExpireAppSessions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.app {
		s.expires = time.Now().Add(-time.Minute)
	}
}

func (a *FakeAuth) record(r *http.Request) string {
	client := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		client = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	a.mu.Lock()
	a.calls = append(a.calls, Call{Path: r.URL.Path, Client: client})
	a.mu.Unlock()
	return client
}

// appPublicAddrOID is Teleport's AppPublicAddrASN1ExtensionOID, the subject
// attribute of an app session certificate that holds the app's public
// address.
var appPublicAddrOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 6}

// newSession creates a session for user with a user TLS certificate. An app
// session's certificate carries publicAddr as Teleport writes it. A web
// session passes "".
func (a *FakeAuth) newSession(user, publicAddr string) (*session, error) {
	subject := a.pki.subject(user)
	if publicAddr != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: appPublicAddrOID, Value: publicAddr}}
	}
	certPEM, keyPEM, err := a.pki.tlsLeaf(subject, nil)
	if err != nil {
		return nil, err
	}
	return &session{
		name:    hex.EncodeToString(randomBytes(16)),
		user:    user,
		bearer:  hex.EncodeToString(randomBytes(16)),
		expires: time.Now().Add(time.Hour),
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}, nil
}

func (a *FakeAuth) newWebSession(user string) (*session, error) {
	s, err := a.newSession(user, "")
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.web[s.name] = s
	a.mu.Unlock()
	return s, nil
}

// gRPC status codes.
const (
	codeInvalidArgument   = 3
	codeNotFound          = 5
	codeAlreadyExists     = 6
	codePermissionDenied  = 7
	codeResourceExhausted = 8
	codeUnimplemented     = 12
)

// The teleport.mfa.v1.ChallengeScope values the hubs use.
const (
	scopePasswordlessLogin = 2
	scopeManageDevices     = 4
)

func (a *FakeAuth) grpc(w http.ResponseWriter, r *http.Request, method string) {
	client := a.record(r)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		grpcStatus(w, codeInvalidArgument, "bad frame")
		return
	}
	req := decodeFields(body[5:])
	a.mu.Lock()
	limited := a.rateLimited
	a.mu.Unlock()
	if limited && (method == "CreateAuthenticateChallenge" || method == "CreateRegisterChallenge") {
		grpcStatus(w, codeResourceExhausted, "too many requests")
		return
	}
	var resp pbMsg
	var code int
	var message string
	switch method {
	case "Ping":
		resp = pbMsg(nil).str(1, a.pki.Cluster)
	case "GetWebSession":
		a.mu.Lock()
		s := a.web[req.str(2)]
		a.mu.Unlock()
		if s == nil || s.user != req.str(1) {
			code, message = codeNotFound, "web session not found"
			break
		}
		resp = pbMsg(nil).msg(1, s.encode())
	case "CreateAppSession":
		user := req.str(1)
		if client != user {
			code, message = codePermissionDenied, fmt.Sprintf("CreateAppSession for %q as %q", user, client)
			break
		}
		s, err := a.newSession(user, req.str(3))
		if err != nil {
			code, message = codeInvalidArgument, err.Error()
			break
		}
		a.mu.Lock()
		a.app[s.name] = s
		a.mu.Unlock()
		resp = pbMsg(nil).msg(1, pbMsg(nil).msg(4, pbMsg(nil).str(1, s.name)))
	case "GetAppSession":
		a.mu.Lock()
		s := a.app[req.str(1)]
		a.mu.Unlock()
		if s == nil {
			code, message = codeNotFound, "app session not found"
			break
		}
		resp = pbMsg(nil).msg(1, s.encode())
	case "CreateAuthenticateChallenge":
		resp, code, message = a.createAuthenticateChallenge(client, req)
	case "CreateRegisterChallenge":
		resp, code, message = a.createRegisterChallenge(client, req)
	case "GetMFADevices":
		resp, code, message = a.getMFADevices(client)
	case "AddMFADeviceSync":
		resp, code, message = a.addMFADeviceSync(client, req)
	case "DeleteMFADeviceSync":
		code, message = a.deleteMFADeviceSync(client, req)
	case "CreatePrivilegeToken":
		resp, code, message = a.createPrivilegeToken(client, req)
	case "ChangeUserAuthentication":
		cred := req.msg(3).msg(3)
		if req.str(1) != BobInvite || string(cred.bytes(2)) != BobCredID {
			code, message = codePermissionDenied, "bad invite or credential"
			break
		}
		s, err := a.newWebSession(Bob)
		if err != nil {
			code, message = codeInvalidArgument, err.Error()
			break
		}
		resp = pbMsg(nil).msg(1, s.encode())
	default:
		code, message = codeUnimplemented, "not implemented by the fake auth"
	}
	if code != 0 {
		grpcStatus(w, code, message)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	frame := make([]byte, 5, 5+len(resp))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(resp)))
	w.Write(append(frame, resp...))
	w.Header().Set("Grpc-Status", "0")
	w.Header().Set("Grpc-Message", "")
}

// createAuthenticateChallenge answers a passwordless login challenge with
// LoginChallenge, or a manage-devices challenge for the user in the client
// certificate with a challenge of its own that one answer uses up.
func (a *FakeAuth) createAuthenticateChallenge(client string, req pbFields) (pbMsg, int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	scope := req.msg(6).int(1)
	var challenge []byte
	var credIDs []string
	switch {
	case req.has(4) && scope == scopePasswordlessLogin:
		challenge = a.LoginChallenge
		credIDs = []string{AliceCredID}
	case req.has(3) && scope == scopeManageDevices:
		if a.devices[client] == nil {
			return nil, codePermissionDenied, fmt.Sprintf("no user %q", client)
		}
		challenge = randomBytes(32)
		a.manageChallenges[string(challenge)] = client
		credIDs = a.credIDs(client)
	default:
		return nil, codeInvalidArgument, "unsupported challenge request"
	}
	opts := pbMsg(nil).bytes(1, challenge).int(2, 60000).str(3, RPID)
	for _, id := range credIDs {
		opts = opts.msg(4, credential(id))
	}
	opts = opts.str(6, "required")
	return pbMsg(nil).msg(3, pbMsg(nil).msg(1, opts)), 0, ""
}

// credIDs returns the credential IDs of user's devices. The caller holds
// a.mu.
func (a *FakeAuth) credIDs(user string) []string {
	var ids []string
	for _, d := range a.devices[user] {
		ids = append(ids, d.CredID)
	}
	return ids
}

// credential returns a webauthn.CredentialDescriptor for credID.
func credential(credID string) pbMsg {
	return pbMsg(nil).str(1, "public-key").bytes(2, []byte(credID))
}

// verifyAssertion checks an MFAAuthenticateResponse as an answer to a
// manage-devices challenge issued to user, and uses the challenge up. The
// challenge is read from the clientDataJSON, which the tests fill in as a
// browser would. Only the challenge and the credential ID are checked.
// The caller holds a.mu.
//
// Auth keeps a login challenge apart from the user's own challenges, so an
// answer to one fails as a missing session, not as a wrong scope.
func (a *FakeAuth) verifyAssertion(user string, resp pbFields) (int, string) {
	webauthn := resp.msg(3)
	var clientData struct {
		Challenge string `json:"challenge"`
	}
	json.Unmarshal(webauthn.msg(3).bytes(1), &clientData)
	challenge, _ := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if a.manageChallenges[string(challenge)] != user {
		return codePermissionDenied, fmt.Sprintf("MFA response validation failed: session data for user %q not found", user)
	}
	delete(a.manageChallenges, string(challenge))
	credID := string(webauthn.bytes(2))
	for _, d := range a.devices[user] {
		if d.CredID == credID {
			return 0, ""
		}
	}
	return codePermissionDenied, fmt.Sprintf("MFA response validation failed: unknown credential %q", credID)
}

// createPrivilegeToken answers with a new privilege token for the user in
// the client certificate after a manage-devices answer. It replaces the
// user's earlier token, as auth does.
func (a *FakeAuth) createPrivilegeToken(client string, req pbFields) (pbMsg, int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.devices[client] == nil {
		return nil, codePermissionDenied, fmt.Sprintf("no user %q", client)
	}
	if !req.has(1) {
		return nil, codeInvalidArgument, "second factor authentication required"
	}
	if code, message := a.verifyAssertion(client, req.msg(1)); code != 0 {
		return nil, code, message
	}
	for id, t := range a.tokens {
		if t.user == client {
			delete(a.tokens, id)
		}
	}
	id := hex.EncodeToString(randomBytes(16))
	t := &userToken{user: client, expires: time.Now().Add(PrivilegeTokenTTL).Truncate(time.Second)}
	a.tokens[id] = t
	meta := pbMsg(nil).str(1, id).msg(6, pbMsg(nil).int(1, t.expires.Unix()))
	return pbMsg(nil).str(1, "user_token").str(2, "privilege").str(3, "v3").msg(4, meta).msg(5, pbMsg(nil).str(1, client)), 0, ""
}

// privilegeTokenUser returns the user of a privilege token that has not
// expired, or "". The caller holds a.mu.
func (a *FakeAuth) privilegeTokenUser(id string) string {
	t := a.tokens[id]
	if t == nil || t.expires.Before(time.Now()) {
		return ""
	}
	return t.user
}

// createRegisterChallenge answers a register challenge for the user of an
// invite or privilege token, or for the user in the client certificate
// after a manage-devices answer. An unknown or expired token gets auth's
// "invalid token".
func (a *FakeAuth) createRegisterChallenge(client string, req pbFields) (pbMsg, int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	user := Bob
	switch {
	case req.str(1) == BobInvite:
	case req.str(1) != "":
		user = a.privilegeTokenUser(req.str(1))
		if user == "" {
			return nil, codePermissionDenied, "invalid token"
		}
	case req.has(4):
		if a.devices[client] == nil {
			return nil, codePermissionDenied, fmt.Sprintf("no user %q", client)
		}
		if code, message := a.verifyAssertion(client, req.msg(4)); code != 0 {
			return nil, code, message
		}
		user = client
	default:
		return nil, codeInvalidArgument, "token or existing MFA response required"
	}
	a.registering[user] = struct{}{}
	opts := pbMsg(nil).
		bytes(1, a.RegisterChallenge).
		msg(2, pbMsg(nil).str(1, RPID).str(2, "sallyport")).
		msg(3, pbMsg(nil).bytes(1, []byte("user-"+user)).str(2, user).str(3, user)).
		msg(4, pbMsg(nil).str(1, "public-key").int(2, -7)).
		int(5, 60000)
	for _, id := range a.credIDs(user) {
		opts = opts.msg(6, credential(id))
	}
	opts = opts.str(7, "none").msg(9, pbMsg(nil).int(2, 1).str(3, "required"))
	return pbMsg(nil).msg(3, pbMsg(nil).msg(1, opts)), 0, ""
}

// getMFADevices lists the devices of the user in the client certificate.
func (a *FakeAuth) getMFADevices(client string) (pbMsg, int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.devices[client] == nil {
		return nil, codePermissionDenied, fmt.Sprintf("no user %q", client)
	}
	var resp pbMsg
	for _, d := range a.devices[client] {
		resp = resp.msg(1, d.encode())
	}
	return resp, 0, ""
}

// addMFADeviceSync adds a passkey for the user of a privilege token, or for
// the user in the client certificate, with the checks auth makes on the
// name and the credential ID, in auth's order. A register challenge must
// have been issued and not finished. The token stays valid until it
// expires, as in auth.
func (a *FakeAuth) addMFADeviceSync(client string, req pbFields) (pbMsg, int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var user string
	switch {
	case req.str(1) != "":
		user = a.privilegeTokenUser(req.str(1))
		if user == "" {
			return nil, codePermissionDenied, "invalid token"
		}
	case req.has(5) && a.devices[client] != nil:
		user = client
	default:
		return nil, codePermissionDenied, fmt.Sprintf("no user %q", client)
	}
	name := req.str(2)
	if len(name) > 30 {
		return nil, codeInvalidArgument, "device name must be 30 characters or less"
	}
	if _, ok := a.registering[user]; !ok {
		return nil, codeNotFound, fmt.Sprintf("session data for user %q not found", user)
	}
	if name == "" {
		return nil, codeInvalidArgument, "device name required"
	}
	credID := string(req.msg(3).msg(3).bytes(2))
	if credID == "" {
		return nil, codeInvalidArgument, "credential required"
	}
	for _, d := range a.devices[user] {
		if d.Name == name {
			return nil, codeAlreadyExists, fmt.Sprintf("MFA device with name %q already exists", name)
		}
		if d.CredID == credID {
			return nil, codeAlreadyExists, fmt.Sprintf("credential ID already in use by device %q", d.Name)
		}
	}
	d := Device{Name: name, CredID: credID, AddedAt: time.Now().Truncate(time.Second)}
	a.devices[user] = append(a.devices[user], d)
	delete(a.registering, user)
	return pbMsg(nil).msg(1, d.encode()), 0, ""
}

// deleteMFADeviceSync deletes a named device of the user in the client
// certificate after a manage-devices answer, except the last one.
func (a *FakeAuth) deleteMFADeviceSync(client string, req pbFields) (int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !req.has(3) {
		return codeInvalidArgument, "deleting an MFA device requires either a privilege token or a solved authentication challenge"
	}
	if a.devices[client] == nil {
		return codePermissionDenied, fmt.Sprintf("no user %q", client)
	}
	if code, message := a.verifyAssertion(client, req.msg(3)); code != 0 {
		return code, message
	}
	name := req.str(2)
	devices := a.devices[client]
	i := slices.IndexFunc(devices, func(d Device) bool { return d.Name == name })
	if i < 0 {
		return codeNotFound, fmt.Sprintf("MFA device %q does not exist", name)
	}
	if len(devices) == 1 {
		return codeInvalidArgument, "cannot delete last passwordless credential for user"
	}
	a.devices[client] = slices.Delete(devices, i, i+1)
	return 0, ""
}

// encode returns the device as a types.MFADevice with the fields the hubs
// read.
func (d Device) encode() pbMsg {
	return pbMsg(nil).
		str(1, "mfa_device").
		str(3, "v1").
		msg(4, pbMsg(nil).str(1, d.Name)).
		str(5, "id-"+d.CredID).
		msg(6, pbMsg(nil).int(1, d.AddedAt.Unix())).
		msg(10, pbMsg(nil).bytes(1, []byte(d.CredID)))
}

// grpcStatus writes a trailers-only gRPC error.
func grpcStatus(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", fmt.Sprint(code))
	w.Header().Set("Grpc-Message", url.PathEscape(message))
	w.WriteHeader(http.StatusOK)
}

func (a *FakeAuth) authenticateWebUser(w http.ResponseWriter, r *http.Request) {
	a.record(r)
	var in struct {
		Username string `json:"username"`
		WebAuthn struct {
			ID string `json:"id"`
		} `json:"webauthn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
		return
	}
	user := a.userOfCredential(in.WebAuthn.ID)
	if in.Username != "" || user == "" {
		http.Error(w, `{"error":{"message":"access denied"}}`, http.StatusForbidden)
		return
	}
	s, err := a.newWebSession(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"kind":     "web_session",
		"version":  "v2",
		"metadata": map[string]string{"name": s.name},
		"spec":     map[string]any{"user": s.user, "bearer_token": s.bearer},
	})
}

// userOfCredential returns the user whose passkey has credID, or "".
func (a *FakeAuth) userOfCredential(credID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for user, devices := range a.devices {
		for _, d := range devices {
			if d.CredID == credID {
				return user
			}
		}
	}
	return ""
}

// encode returns the session as a types.WebSessionV2 with the fields the
// hubs read.
func (s *session) encode() pbMsg {
	spec := pbMsg(nil).
		str(1, s.user).
		bytes(3, s.keyPEM).
		bytes(4, s.certPEM).
		str(5, s.bearer).
		msg(7, pbMsg(nil).int(1, s.expires.Unix())).
		bytes(15, s.keyPEM)
	return pbMsg(nil).str(1, "web_session").str(3, "v2").msg(4, pbMsg(nil).str(1, s.name)).msg(5, spec)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// pbMsg builds a protobuf message. Empty strings and bytes and zero
// numbers are left out, as in proto3.
type pbMsg []byte

func (m pbMsg) str(n protowire.Number, s string) pbMsg {
	if s == "" {
		return m
	}
	return protowire.AppendString(protowire.AppendTag(m, n, protowire.BytesType), s)
}

func (m pbMsg) bytes(n protowire.Number, b []byte) pbMsg {
	if len(b) == 0 {
		return m
	}
	return protowire.AppendBytes(protowire.AppendTag(m, n, protowire.BytesType), b)
}

func (m pbMsg) msg(n protowire.Number, sub pbMsg) pbMsg {
	return protowire.AppendBytes(protowire.AppendTag(m, n, protowire.BytesType), sub)
}

func (m pbMsg) int(n protowire.Number, v int64) pbMsg {
	if v == 0 {
		return m
	}
	return protowire.AppendVarint(protowire.AppendTag(m, n, protowire.VarintType), uint64(v))
}

// pbFields is a decoded message. Only varint and length-delimited fields
// are kept, the last value of each. A varint is kept as its encoding.
type pbFields map[protowire.Number][]byte

func decodeFields(b []byte) pbFields {
	f := pbFields{}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return f
		}
		b = b[n:]
		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return f
			}
			f[num] = v
			b = b[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return f
			}
			f[num] = b[:n]
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return f
			}
			b = b[n:]
		}
	}
	return f
}

func (f pbFields) str(n protowire.Number) string   { return string(f[n]) }
func (f pbFields) bytes(n protowire.Number) []byte { return f[n] }
func (f pbFields) msg(n protowire.Number) pbFields { return decodeFields(f[n]) }

// has reports whether field n is set, even to an empty message.
func (f pbFields) has(n protowire.Number) bool {
	_, ok := f[n]
	return ok
}

// int returns a varint field, or 0.
func (f pbFields) int(n protowire.Number) int64 {
	v, m := protowire.ConsumeVarint(f[n])
	if m < 0 {
		return 0
	}
	return int64(v)
}
