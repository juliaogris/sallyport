//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Forwards one browser HTTP request to a Teleport app service.
//
// The hub opens teleport-transport into the agent with an @local-node dial
// request, then runs TLS with the user's app session certificate. The app
// service picks the app and the session from that certificate. HTTP/1.1
// runs over the TLS stream, and the response streams back to the browser
// as it arrives.

// apiDomain is the SNI suffix the app service expects after the hex
// cluster name (api/utils/cluster.go, EncodeClusterName).
const apiDomain = "teleport.cluster.local"

// spCookiePrefix is the prefix of the session cookies the hub itself sets.
// The app service never sees them, and the app cannot set them.
const spCookiePrefix = "__Host-sp_"

// errSwitchingProtocols is the error for a 101 from the app, which has its
// own 502 body. Every other failure gets the same fixed body.
var errSwitchingProtocols = errors.New("app answered 101 Switching Protocols")

// appDialer opens a connection to the app service: a channel of the agent
// tunnel, or a stream from auth's callout in the lazy hub.
type appDialer func(ctx context.Context) (net.Conn, error)

// tunnelDialer returns the appDialer that dials into the agent over t.
func tunnelDialer(t *appTunnel) appDialer {
	return func(context.Context) (net.Conn, error) {
		ch, err := t.dial()
		if err != nil {
			return nil, err
		}
		return chanConn{ch}, nil
	}
}

// appDialer returns the appDialer that asks auth's callout for an app
// stream.
func (l *lazyHub) appDialer() appDialer {
	return func(ctx context.Context) (net.Conn, error) { return l.dial(ctx, "app") }
}

// forward sends req to the app service at host over a connection from
// dial, as the user with the given certificate. A dial, TLS or HTTP failure logs the
// error and returns a 502 "app unavailable". A 101 from the app returns a
// 502 that says so.
func (h *hub) forward(dial appDialer, cert tls.Certificate, host string, req *request) *response {
	res, err := h.forwardInner(dial, cert, host, req)
	if errors.Is(err, errSwitchingProtocols) {
		logf("appproxy: %v", err)
		return textError(err.Error(), 502)
	}
	if err != nil {
		logf("appproxy: %v", err)
		return textError("app unavailable", 502)
	}
	return res
}

func (h *hub) forwardInner(dial appDialer, cert tls.Certificate, host string, req *request) (*response, error) {
	if err := h.cfg.err("HOST_CA_TLS"); err != nil {
		return nil, err
	}
	sni := hex.EncodeToString([]byte(h.cfg.cluster)) + "." + apiDomain
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	tr := &http.Transport{
		Protocols:          protos,
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dial(ctx)
			if err != nil {
				return nil, err
			}
			// The handshake on a lazy stream must finish within
			// lazyDialDeadline. A tunnel channel has no such deadline.
			if h.lazy != nil {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, lazyDialDeadline)
				defer cancel()
			}
			tc := tls.Client(conn, &tls.Config{
				ServerName:   sni,
				RootCAs:      h.cfg.hostCATLS,
				Certificates: []tls.Certificate{cert},
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("tls connect: %w", err)
			}
			return tc, nil
		},
	}
	cc, err := tr.NewClientConn(context.Background(), "https", host+":443")
	if err != nil {
		return nil, err
	}
	up, err := buildRequest(req, host)
	if err != nil {
		cc.Close()
		return nil, err
	}
	resp, err := cc.RoundTrip(up)
	if err != nil {
		cc.Close()
		return nil, fmt.Errorf("app request: %w", err)
	}
	// A 101 cannot be forwarded. The hub sends no Upgrade header upstream.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		closeBoth{resp.Body, cc}.Close()
		return nil, errSwitchingProtocols
	}
	return buildResponse(resp, cc), nil
}

// hopByHop are the header names that describe one hop of the connection,
// per RFC 7230 6.1, plus the ones browsers and proxies add in practice.
// None are forwarded in either direction.
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
}

// buildRequest builds the request the hub sends upstream: the method and
// path of req, its headers without the hop-by-hop, Host and cf-* ones,
// Host set to host, and the hub's own session cookies removed.
func buildRequest(req *request, host string) (*http.Request, error) {
	var body io.Reader
	if req.method != "GET" && req.method != "HEAD" {
		body = bytes.NewReader(req.body)
	}
	up, err := http.NewRequest(req.method, "https://"+host+req.path+req.query, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for name, value := range req.header {
		switch {
		case name == "host", strings.HasPrefix(name, "cf-"), hopByHop[name]:
			continue
		case name == "cookie":
			if kept := stripSPCookies(value); kept != "" {
				up.Header["Cookie"] = []string{kept}
			}
			continue
		}
		up.Header[http.CanonicalHeaderKey(name)] = []string{value}
	}
	// Go adds a User-Agent of its own unless the header is set.
	if _, ok := up.Header["User-Agent"]; !ok {
		up.Header["User-Agent"] = []string{""}
	}
	up.Host = host
	return up, nil
}

// stripSPCookies removes every cookie whose name starts with
// spCookiePrefix from a Cookie header value, and returns "" when nothing
// is left.
func stripSPCookies(value string) string {
	var kept []string
	for _, c := range strings.Split(value, ";") {
		c = strings.TrimSpace(c)
		if c != "" && !strings.HasPrefix(c, spCookiePrefix) {
			kept = append(kept, c)
		}
	}
	return strings.Join(kept, "; ")
}

// buildResponse turns the app service's response into the hub's, with the
// hop-by-hop headers dropped and the body streamed as it arrives. The
// stream closes cc when it ends.
func buildResponse(resp *http.Response, cc *http.ClientConn) *response {
	if resp.StatusCode >= 500 {
		logf("appproxy: upstream %s %q", resp.Status, resp.Header.Get("Server"))
	}
	res := &response{status: resp.StatusCode}
	for name, values := range resp.Header {
		lower := strings.ToLower(name)
		if hopByHop[lower] {
			continue
		}
		for _, v := range values {
			// The app must not replace or clear the hub's own session
			// cookies.
			if lower == "set-cookie" && strings.HasPrefix(strings.TrimLeft(v, " \t"), spCookiePrefix) {
				continue
			}
			res.add(lower, v)
		}
	}
	var body io.ReadCloser = closeBoth{resp.Body, cc}
	if resp.ContentLength >= 0 {
		body = &exactBody{body, resp.ContentLength}
	}
	// The runtime refuses a body on these statuses.
	switch resp.StatusCode {
	case 204, 205, 304:
		body.Close()
		return res
	}
	// The runtime compresses a body to match Content-Encoding by default,
	// so an app's gzipped body would be compressed twice.
	if resp.Header.Get("Content-Encoding") != "" {
		res.manual = true
	}
	res.stream = newBodyStream(body)
	return res
}

// exactBody is a body of known length that reports the end with its last
// bytes, since the runtime stops reading once it has them.
type exactBody struct {
	io.ReadCloser
	left int64
}

func (b *exactBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

// closeBoth is a response body that also closes its connection.
type closeBoth struct {
	io.ReadCloser
	cc *http.ClientConn
}

func (c closeBoth) Close() error {
	c.ReadCloser.Close()
	return c.cc.Close()
}

// chanConn is a net.Conn over an SSH channel, for TLS.
type chanConn struct{ ssh.Channel }

func (chanConn) LocalAddr() net.Addr              { return wsAddr{} }
func (chanConn) RemoteAddr() net.Addr             { return wsAddr{} }
func (chanConn) SetDeadline(time.Time) error      { return nil }
func (chanConn) SetReadDeadline(time.Time) error  { return nil }
func (chanConn) SetWriteDeadline(time.Time) error { return nil }
