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
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Forwards one browser HTTP request to a Teleport app service.
//
// The hub opens teleport-transport into the agent with an @local-node dial
// request, or asks auth's callout for an app stream in the lazy hub, then
// runs TLS with the user's app session certificate. The app service picks
// the app and the session from that certificate. HTTP/1.1 runs over the
// TLS stream, and the response streams back to the browser as it arrives.
// The requests of one app session share up to appConnsPerSession
// connections, which close after appConnIdle without a request.

// apiDomain is the SNI suffix the app service expects after the hex
// cluster name (api/utils/cluster.go, EncodeClusterName).
const apiDomain = "teleport.cluster.local"

// spCookiePrefix is the prefix of the session cookies the hub itself sets.
// The app service never sees them, and the app cannot set them.
const spCookiePrefix = "__Host-sp_"

const (
	// appConnsPerSession is the most connections that the requests of one
	// app session use at once. A request above that waits for one.
	appConnsPerSession = 32
	// appConnIdle closes a connection that has had no request for this
	// long. A lazy stream keeps the Durable Object awake while it is open.
	appConnIdle = 5 * time.Second
	// appConnDeadline is how long a request may wait for a connection,
	// including the dial and the TLS handshake.
	appConnDeadline = 20 * time.Second
	// appHandshakeDeadline is how long the TLS handshake with the app
	// service may take. A lazy stream and a tunnel channel have no
	// deadlines, so a peer that went away would block the handshake
	// otherwise.
	appHandshakeDeadline = 10 * time.Second
)

// errSwitchingProtocols is the error for a 101 from the app, which has its
// own 502 body. Every other failure gets the same fixed body.
var errSwitchingProtocols = errors.New("app answered 101 Switching Protocols")

// dialApp opens a connection to the app service: a channel of the agent
// tunnel, or a stream from auth's callout in the lazy hub.
func (h *hub) dialApp(ctx context.Context) (net.Conn, error) {
	if h.lazy != nil {
		return h.lazy.dial(ctx, "app")
	}
	h.appMu.Lock()
	t := h.appTunnel
	h.appMu.Unlock()
	if t == nil {
		return nil, errors.New("no app tunnel")
	}
	ch, err := t.dial()
	if err != nil {
		return nil, err
	}
	return chanConn{ch}, nil
}

// forward sends req to the app service at host, as the user of the app
// session sid with the given certificate. A dial, TLS or HTTP failure logs
// the error and returns a 502 "app unavailable". A dial that auth's
// callout refused returns a 503 "app service busy". A 101 from the app
// returns a 502 that says so.
func (h *hub) forward(sid string, cert tls.Certificate, host string, req *request) *response {
	res, err := h.forwardInner(sid, cert, host, req)
	if errors.Is(err, errSwitchingProtocols) {
		logf("appproxy: %v", err)
		return textError(err.Error(), 502)
	}
	if errors.Is(err, errDialRefused) {
		logf("appproxy: %v", err)
		return textError("app service busy", 503)
	}
	if err != nil {
		logf("appproxy: %v", err)
		return textError("app unavailable", 502)
	}
	return res
}

func (h *hub) forwardInner(sid string, cert tls.Certificate, host string, req *request) (*response, error) {
	if err := h.cfg.err("HOST_CA_TLS"); err != nil {
		return nil, err
	}
	tr := h.appTransports.get(sid, time.Now(), func() *http.Transport { return h.appTransport(cert) })
	up, err := buildRequest(req, host)
	if err != nil {
		return nil, err
	}
	// The context ends when the response body closes. Until the request
	// has a connection, it ends after appConnDeadline.
	ctx, cancel := context.WithCancel(context.Background())
	connTimer := time.AfterFunc(appConnDeadline, cancel)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connTimer.Stop() },
	})
	if req.bodyReader != nil {
		// The app may answer before it has read the whole body, and the
		// transport then keeps reading it until the browser ends it.
		done := cancel
		cancel = func() {
			done()
			req.bodyReader.Close()
		}
	}
	resp, err := tr.RoundTrip(up.WithContext(ctx))
	connTimer.Stop()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("app request: %w", err)
	}
	// A 101 to a request without Upgrade cannot be forwarded. The hub sends
	// no Upgrade header upstream on a plain request.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		closeBoth{resp.Body, cancel}.Close()
		return nil, errSwitchingProtocols
	}
	return buildResponse(resp, cancel), nil
}

// appTransport returns a transport that connects to the app service with
// cert, for the requests of one app session.
func (h *hub) appTransport(cert tls.Certificate) *http.Transport {
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	return &http.Transport{
		Protocols:           protos,
		DisableCompression:  true,
		MaxConnsPerHost:     appConnsPerSession,
		MaxIdleConnsPerHost: appConnsPerSession,
		IdleConnTimeout:     appConnIdle,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return h.dialAppTLS(ctx, cert)
		},
	}
}

// dialAppTLS opens a connection to the app service and runs TLS on it with
// cert.
func (h *hub) dialAppTLS(ctx context.Context, cert tls.Certificate) (net.Conn, error) {
	conn, err := h.dialApp(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, appHandshakeDeadline)
	defer cancel()
	tc := tls.Client(conn, &tls.Config{
		ServerName:   hex.EncodeToString([]byte(h.cfg.cluster)) + "." + apiDomain,
		RootCAs:      h.cfg.hostCATLS,
		Certificates: []tls.Certificate{cert},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls connect: %w", err)
	}
	return tc, nil
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
		if req.bodyReader != nil {
			body = req.bodyReader
		}
	}
	up, err := http.NewRequest(req.method, "https://"+host+req.path+req.query, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if req.bodyReader != nil && body != nil {
		// The transport closes the body once it has sent it or failed.
		req.bodyTaken = true
		up.ContentLength = -1
		if n, err := strconv.ParseInt(req.header["content-length"], 10, 64); err == nil {
			up.ContentLength = n
		}
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
// stream calls done when it ends.
func buildResponse(resp *http.Response, done context.CancelFunc) *response {
	if resp.StatusCode >= 500 {
		logf("appproxy: upstream %s %q", resp.Status, resp.Header.Get("Server"))
	}
	res := &response{status: resp.StatusCode}
	// The runtime compresses a body to match Content-Encoding by default,
	// so an app's gzipped body would be compressed twice. The runtime and
	// the edge also compress a text body for a browser that accepts gzip or
	// brotli, and the compressor holds a body of unknown length until it
	// ends, which breaks a long-held stream such as SockJS xhr_streaming.
	// Neither compresses a body that has a Content-Encoding, so such a body
	// is sent as identity.
	encoded := resp.Header.Get("Content-Encoding") != ""
	res.manual = encoded || resp.ContentLength < 0
	if !encoded && resp.ContentLength < 0 {
		res.add("content-encoding", "identity")
	}
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
	var body io.ReadCloser = closeBoth{resp.Body, done}
	if resp.ContentLength >= 0 {
		body = &exactBody{body, resp.ContentLength}
	}
	// The runtime refuses a body on these statuses. A HEAD response has no
	// body, though it may have a Content-Length.
	switch {
	case resp.StatusCode == 204, resp.StatusCode == 205, resp.StatusCode == 304,
		resp.Request != nil && resp.Request.Method == "HEAD":
		body.Close()
		return res
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

// closeBoth is a response body that also ends its request's context when
// it closes.
type closeBoth struct {
	io.ReadCloser
	done context.CancelFunc
}

func (c closeBoth) Close() error {
	err := c.ReadCloser.Close()
	c.done()
	return err
}

// chanConn is a net.Conn over an SSH channel, for TLS.
type chanConn struct{ ssh.Channel }

func (chanConn) LocalAddr() net.Addr              { return wsAddr{} }
func (chanConn) RemoteAddr() net.Addr             { return wsAddr{} }
func (chanConn) SetDeadline(time.Time) error      { return nil }
func (chanConn) SetReadDeadline(time.Time) error  { return nil }
func (chanConn) SetWriteDeadline(time.Time) error { return nil }
