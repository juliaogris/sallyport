package conformance

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protowire"
)

// The test users. Alice has a passkey. Bob has an invite.
const (
	Alice       = "alice"
	AliceCredID = "cred-alice"
	Bob         = "bob"
	BobInvite   = "tok-bob"
	BobCredID   = "cred-bob"
	RPID        = LoginHost
)

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
	// LoginChallenge is the challenge in every login challenge.
	LoginChallenge []byte
	// RegisterChallenge is the challenge in every register challenge.
	RegisterChallenge []byte
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

// newSession creates a session for user with a user TLS certificate.
func (a *FakeAuth) newSession(user string) (*session, error) {
	certPEM, keyPEM, err := a.pki.tlsLeaf(user, nil)
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
	s, err := a.newSession(user)
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
	codeInvalidArgument  = 3
	codeNotFound         = 5
	codePermissionDenied = 7
	codeUnimplemented    = 12
)

func (a *FakeAuth) grpc(w http.ResponseWriter, r *http.Request, method string) {
	client := a.record(r)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		grpcStatus(w, codeInvalidArgument, "bad frame")
		return
	}
	req := decodeFields(body[5:])
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
		s, err := a.newSession(user)
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
		cred := pbMsg(nil).str(1, "public-key").bytes(2, []byte(AliceCredID))
		opts := pbMsg(nil).bytes(1, a.LoginChallenge).int(2, 60000).str(3, RPID).msg(4, cred).str(6, "required")
		resp = pbMsg(nil).msg(3, pbMsg(nil).msg(1, opts))
	case "CreateRegisterChallenge":
		if req.str(1) != BobInvite {
			code, message = codeNotFound, "invite not found"
			break
		}
		opts := pbMsg(nil).
			bytes(1, a.RegisterChallenge).
			msg(2, pbMsg(nil).str(1, RPID).str(2, "sallyport")).
			msg(3, pbMsg(nil).bytes(1, []byte("user-bob")).str(2, Bob).str(3, Bob)).
			msg(4, pbMsg(nil).str(1, "public-key").int(2, -7)).
			int(5, 60000).
			str(7, "none").
			msg(9, pbMsg(nil).int(2, 1).str(3, "required"))
		resp = pbMsg(nil).msg(3, pbMsg(nil).msg(1, opts))
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
	if in.Username != "" || in.WebAuthn.ID != AliceCredID {
		http.Error(w, `{"error":{"message":"access denied"}}`, http.StatusForbidden)
		return
	}
	s, err := a.newWebSession(Alice)
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
// are kept, the last value of each.
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
