//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Unary gRPC calls to auth over an auth pipe stream.
//
// The hub runs TLS to auth with SNI teleport.cluster.local and ALPN h2,
// verifies auth's certificate against the cluster host CA, and presents a
// client certificate: the hub TLS identity or a user's certificate.
// net/http's HTTP/2 client carries the calls, with the gRPC framing
// written by hand.
const (
	// authSNI selects auth's default CA pool.
	authSNI = "teleport.cluster.local"
	// callDeadline is the deadline of every call to auth.
	callDeadline = 5 * time.Second

	createAppSession            = "/proto.AuthService/CreateAppSession"
	getAppSession               = "/proto.AuthService/GetAppSession"
	createAuthenticateChallenge = "/proto.AuthService/CreateAuthenticateChallenge"
	getWebSession               = "/proto.AuthService/GetWebSession"
	createRegisterChallenge     = "/proto.AuthService/CreateRegisterChallenge"
	changeUserAuthentication    = "/proto.AuthService/ChangeUserAuthentication"
	getMFADevices               = "/proto.AuthService/GetMFADevices"
	addMFADeviceSync            = "/proto.AuthService/AddMFADeviceSync"
	deleteMFADeviceSync         = "/proto.AuthService/DeleteMFADeviceSync"
	createPrivilegeToken        = "/proto.AuthService/CreatePrivilegeToken"
	// authenticateWebUserPasswordless is the legacy HTTP route for
	// AuthenticateWebUser. A passwordless login has an empty user, so the
	// path has an empty segment, as the Go proxy sends it.
	authenticateWebUserPasswordless = "/v2/users//web/authenticate"
)

// grpcError is a call that auth answered with a gRPC error status. It is
// not retried.
type grpcError struct {
	path, status, message string
	httpStatus            int
}

func (e *grpcError) Error() string {
	return fmt.Sprintf("%s: http %d, grpc-status %q: %s", e.path, e.httpStatus, e.status, e.message)
}

// rateLimitedMsg is the body of the 429 for a call that auth refused with
// ResourceExhausted, the same as the Rust hub's.
const rateLimitedMsg = "too many requests, try again in a minute"

// rateLimited returns true when auth answered the call in err with gRPC
// status ResourceExhausted, which it does when its rate limit is reached.
func rateLimited(err error) bool {
	var ge *grpcError
	return errors.As(err, &ge) && ge.status == "8"
}

// authTLS returns the TLS client config toward auth with the given client
// certificate.
func (h *hub) authTLS(cert tls.Certificate, alpn ...string) *tls.Config {
	return &tls.Config{
		ServerName:   authSNI,
		RootCAs:      h.cfg.hostCATLS,
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
	}
}

// connectAuth runs TLS and opens an HTTP client connection to auth on a
// new auth pipe stream. With h2 it offers ALPN h2 and requires it, for
// gRPC. Without, it offers no ALPN and speaks HTTP/1.1, for auth's legacy
// HTTP API, since h2 on auth goes to gRPC.
func (h *hub) connectAuth(ctx context.Context, cert tls.Certificate, h2 bool) (*http.ClientConn, error) {
	if err := h.cfg.err("HOST_CA_TLS"); err != nil {
		return nil, err
	}
	var alpn []string
	protos := new(http.Protocols)
	if h2 {
		alpn = []string{"h2"}
		protos.SetHTTP2(true)
	} else {
		protos.SetHTTP1(true)
	}
	tr := &http.Transport{
		Protocols:          protos,
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			stream, err := h.authStream(ctx)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(stream, h.authTLS(cert, alpn...))
			if err := tc.HandshakeContext(ctx); err != nil {
				stream.Close()
				return nil, fmt.Errorf("tls to auth: %w", err)
			}
			if got := tc.ConnectionState().NegotiatedProtocol; h2 && got != "h2" {
				tc.Close()
				return nil, fmt.Errorf("auth chose ALPN %q, want h2", got)
			}
			return tc, nil
		},
	}
	return tr.NewClientConn(ctx, "https", authSNI+":443")
}

// authStream returns a stream to auth: a dial of kind auth in the lazy
// hub, and otherwise a stream from the auth pipe pool.
func (h *hub) authStream(ctx context.Context) (net.Conn, error) {
	if h.lazy != nil {
		return h.lazy.dial(ctx, "auth")
	}
	if stream := h.pool.take(); stream != nil {
		return stream, nil
	}
	return nil, errors.New("no auth pipe stream")
}

// unary makes one unary call within callDeadline and returns the response
// message. The error is a *grpcError for a gRPC status, or the transport
// error.
func unary(cc *http.ClientConn, path string, msg []byte) (fields, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callDeadline)
	defer cancel()
	frame := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	frame = append(frame, msg...)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+authSNI+path, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/grpc")
	req.Header.Set("te", "trailers")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// A call that fails before any data sends its status in the headers.
	status, message := resp.Trailer.Get("grpc-status"), resp.Trailer.Get("grpc-message")
	if status == "" {
		status, message = resp.Header.Get("grpc-status"), resp.Header.Get("grpc-message")
	}
	if status != "0" {
		m, err := url.PathUnescape(message)
		if err != nil {
			m = message
		}
		return nil, &grpcError{path: path, status: status, message: m, httpStatus: resp.StatusCode}
	}
	if len(data) < 5 || data[0] != 0 {
		return nil, fmt.Errorf("%s: bad gRPC frame", path)
	}
	n := binary.BigEndian.Uint32(data[1:5])
	if uint64(len(data)-5) < uint64(n) {
		return nil, fmt.Errorf("%s: short gRPC frame", path)
	}
	out, err := decode(data[5 : 5+n])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// postJSON sends one JSON POST to auth's legacy HTTP API on its own stream,
// within callDeadline. It returns the HTTP status and the body.
func (h *hub) postJSON(cert tls.Certificate, path string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callDeadline)
	defer cancel()
	cc, err := h.connectAuth(ctx, cert, false)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", path, err)
	}
	defer cc.Close()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+authSNI+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Close = true
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	// Auth may close without a TLS close_notify.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, nil, fmt.Errorf("%s: %w", path, err)
	}
	return resp.StatusCode, b, nil
}

// hubAuth is one HTTP/2 connection to auth with the hub TLS identity,
// reused across calls. A call that fails at the transport opens a new
// connection from the pool and is retried once. A gRPC error status is not
// retried.
//
// The lock is held while a connection opens, so callers that arrive
// together share one connection instead of each taking a pool stream.
//
// In the lazy hub the connection closes after authConnIdle without a call,
// because its stream keeps the Durable Object awake while it is open.
type hubAuth struct {
	h  *hub
	mu sync.Mutex
	// gen counts connections opened.
	gen uint64
	cc  *http.ClientConn
	// calls counts the calls in progress, and used is when the last one
	// ended. idle closes cc in the lazy hub.
	calls int
	used  time.Time
	idle  *time.Timer
}

// authConnIdle closes the lazy hub's connection to auth after this long
// without a call.
const authConnIdle = 5 * time.Second

// begin counts a call in progress, and done counts its end.
func (a *hubAuth) begin() {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
}

func (a *hubAuth) done() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls--
	a.used = time.Now()
	if a.h.lazy == nil {
		return
	}
	if a.idle == nil {
		a.idle = time.AfterFunc(authConnIdle, a.closeIdle)
	} else {
		a.idle.Reset(authConnIdle)
	}
}

// closeIdle closes the connection if no call has used it for
// authConnIdle.
func (a *hubAuth) closeIdle() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.calls == 0 && a.cc != nil && time.Since(a.used) >= authConnIdle {
		a.cc.Close()
		a.cc = nil
	}
}

// conn returns the cached connection and its generation if it still
// works. When broken names the cached generation, that connection failed,
// so a new one is opened. A caller whose broken connection another caller
// already replaced gets the replacement.
func (a *hubAuth) conn(broken uint64) (uint64, *http.ClientConn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cc != nil && a.gen != broken && a.cc.Err() == nil {
		return a.gen, a.cc, nil
	}
	if a.cc != nil {
		a.cc.Close()
		a.cc = nil
	}
	if err := a.h.cfg.err("HUB_TLS_CERT", "HUB_TLS_KEY"); err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), callDeadline)
	defer cancel()
	cc, err := a.h.connectAuth(ctx, *a.h.cfg.tlsCert, true)
	if err != nil {
		return 0, nil, err
	}
	a.gen++
	a.cc = cc
	return a.gen, cc, nil
}

// call makes one unary call with the hub identity.
func (a *hubAuth) call(path string, msg []byte) (fields, error) {
	a.begin()
	defer a.done()
	gen, cc, err := a.conn(0)
	if err != nil {
		return nil, err
	}
	out, err := unary(cc, path, msg)
	var ge *grpcError
	if err == nil || errors.As(err, &ge) {
		return out, err
	}
	logf("authrpc: %v, reconnecting", err)
	_, cc, err = a.conn(gen)
	if err != nil {
		return nil, err
	}
	return unary(cc, path, msg)
}

// callAs makes one unary call on a new connection with a user's
// certificate.
func (h *hub) callAs(cert tls.Certificate, path string, msg []byte) (fields, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callDeadline)
	defer cancel()
	cc, err := h.connectAuth(ctx, cert, true)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	return unary(cc, path, msg)
}
