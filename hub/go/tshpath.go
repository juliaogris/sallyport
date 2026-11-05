//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// tshHelloWait is how long the client has to send its inner
	// ClientHello after the upgrade.
	tshHelloWait = 10 * time.Second
	// tshUpgradeLife is the longest an upgrade stays open.
	tshUpgradeLife = 12 * time.Hour
	// tshQueueMax is the most bytes from the client that may wait for the
	// proxy. Above it the upgrade closes with 1009.
	tshQueueMax = 4 << 20
	// tshDeadline bounds the dial, the TLS handshake and the request or
	// WebSocket handshake to the proxy.
	tshDeadline = 20 * time.Second
)

// tshEnabled reports whether the tsh path is on for app: the lazy hub, an
// app in WEB_UI_APPS, and PROXY_WEB_ADDR set.
func (h *hub) tshEnabled(app string) bool {
	return h.lazy != nil && h.cfg.webUIApps[app] && h.cfg.proxyWebAddr != ""
}

// tshRequest answers a request on the tsh path. The caller has checked
// the route and that the request carries no hub cookie.
func (h *hub) tshRequest(req *request, route tshRoute) *response {
	if err := h.cfg.err("PROXY_WEB_ADDR", "PROXY_WEB_CA"); err != nil || h.cfg.proxyWebCA == nil {
		logf("tsh: %v", err)
		return textError("proxy unavailable", 502)
	}
	if !h.lazy.connected() {
		return textError("proxy offline", 503)
	}
	if route == tshUpgrade {
		return h.tshUpgrade(req)
	}
	res, err := h.tshHTTP(req, route)
	if errors.Is(err, errDialRefused) {
		logf("tsh: %v", err)
		return textError("proxy busy", 503)
	}
	if err != nil {
		logf("tsh: %s %s: %v", req.method, req.path, err)
		return textError("proxy unavailable", 502)
	}
	return res
}

// dialProxyTLS opens a proxy stream and runs TLS on it to the home proxy's
// web listener. It verifies the proxy's web certificate for the host of
// PROXY_WEB_ADDR against PROXY_WEB_CA, and never skips verification.
func (h *hub) dialProxyTLS(ctx context.Context) (net.Conn, error) {
	conn, err := h.lazy.dial(ctx, "proxy")
	if err != nil {
		return nil, err
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName: h.cfg.proxyWebHost,
		RootCAs:    h.cfg.proxyWebCA,
		NextProtos: []string{"http/1.1"},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls connect: %w", err)
	}
	return tc, nil
}

// tshHeader returns the headers to send the proxy: the client's, without
// the ones tshHeaderDropped names, with Host set to PROXY_WEB_ADDR and
// X-Forwarded-For set to the client address Cloudflare saw.
func (h *hub) tshHeader(req *request) http.Header {
	out := http.Header{}
	for name, value := range req.header {
		if !tshHeaderDropped(name) {
			out[http.CanonicalHeaderKey(name)] = []string{value}
		}
	}
	if ip := req.header["cf-connecting-ip"]; ip != "" {
		out["X-Forwarded-For"] = []string{ip}
	}
	if _, ok := out["User-Agent"]; !ok {
		out["User-Agent"] = []string{""}
	}
	return out
}

// tshHTTP sends one ping or login request to the proxy on its own proxy
// stream. A stream per request lets the fork's proxy dial budget bound
// the login challenges a client can ask for.
func (h *hub) tshHTTP(req *request, route tshRoute) (*response, error) {
	var body io.Reader
	if req.method == "POST" {
		var src io.Reader = bytes.NewReader(req.body)
		if req.bodyReader != nil {
			src = req.bodyReader
		}
		b, err := io.ReadAll(io.LimitReader(src, tshBodyMax+1))
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		if len(b) > tshBodyMax {
			return textError("request body too large", 413), nil
		}
		body = bytes.NewReader(b)
	}
	up, err := http.NewRequest(req.method, "https://"+h.cfg.proxyWebAddr+req.path+req.query, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	up.Header = h.tshHeader(req)
	delete(up.Header, "Content-Length")
	up.Host = h.cfg.proxyWebAddr

	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	tr := &http.Transport{
		Protocols:          protos,
		DisableCompression: true,
		DisableKeepAlives:  true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return h.dialProxyTLS(ctx)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), tshDeadline)
	resp, err := tr.RoundTrip(up.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("proxy request: %w", err)
	}
	if route != tshPing || resp.StatusCode != http.StatusOK {
		res := buildResponse(resp, cancel)
		return res, nil
	}
	defer cancel()
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, tshPingMax+1))
	if err != nil {
		return nil, fmt.Errorf("read ping: %w", err)
	}
	if len(b) > tshPingMax {
		return nil, errors.New("ping answer too large")
	}
	out, err := rewritePing(b, h.cfg.tshPublicAddr(req.host))
	if err != nil {
		return nil, fmt.Errorf("rewrite ping: %w", err)
	}
	res := &response{status: 200, body: string(out)}
	res.add("content-type", "application/json")
	res.add("content-length", strconv.Itoa(len(out)))
	res.add("cache-control", "no-store")
	return res, nil
}

// tshPublicAddr is the address the rewritten ping gives tsh: the app host
// it asked, on port 443.
func (c *config) tshPublicAddr(host string) string { return host + ":443" }

// tshUpgrade accepts the client's WebSocket, gates its inner ClientHello,
// and only then dials a proxy stream and the proxy's connection upgrade.
// The bytes then cross as binary messages in both directions.
func (h *hub) tshUpgrade(req *request) *response {
	sub := pickSubprotocol(req.header["sec-websocket-protocol"])
	ip := req.header["cf-connecting-ip"]
	if !h.tshCaps.acquire(ip) {
		logf("tsh: upgrade cap reached for a client")
		return textError("too many connections", 429)
	}
	b := newBrowserWS()
	b.maxQueued = tshQueueMax
	b.onDone = func() { h.tshCaps.release(ip) }
	go h.tshGate(b, req, sub)
	res := &response{status: 101, browser: b}
	res.add("sec-websocket-protocol", sub)
	return res
}

// tshGate waits for the inner ClientHello, checks it with gateHello, and
// connects b to the proxy's connection upgrade. A ClientHello that fails
// the gate closes the client's WebSocket with 1008 and opens no stream.
func (h *hub) tshGate(b *browserWS, req *request, sub string) {
	_, err := b.waitBinary(tshHelloWait, func(data []byte) error {
		if len(data) > tshHelloMax {
			return fmt.Errorf("client hello over %d bytes", tshHelloMax)
		}
		hello, err := parseClientHello(data)
		if err != nil {
			return err
		}
		return gateHello(hello, h.cfg.cluster)
	})
	if err != nil {
		logf("tsh: upgrade refused: %v", err)
		b.closeBrowser(websocket.ClosePolicyViolation, "refused")
		b.finish()
		return
	}
	d := &websocket.Dialer{
		NetDialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return h.dialProxyTLS(ctx)
		},
		HandshakeTimeout: tshDeadline,
		Subprotocols:     []string{sub},
	}
	ctx, cancel := context.WithTimeout(context.Background(), tshDeadline)
	defer cancel()
	header := h.tshHeader(req)
	header["Host"] = []string{h.cfg.proxyWebAddr}
	delete(header, "Sec-Websocket-Protocol")
	up, resp, err := d.DialContext(ctx, "wss://"+h.cfg.proxyWebAddr+req.path+req.query, header)
	if err != nil {
		if resp != nil {
			logf("tsh: proxy refused the upgrade with %s", resp.Status)
		} else {
			logf("tsh: upgrade: %v", err)
		}
		code := websocket.CloseInternalServerErr
		if errors.Is(err, errDialRefused) {
			code = websocket.CloseTryAgainLater
		}
		b.closeBrowser(code, "proxy unavailable")
		b.finish()
		return
	}
	if up.Subprotocol() != sub {
		logf("tsh: proxy chose subprotocol %q, not %q", up.Subprotocol(), sub)
		up.Close()
		b.closeBrowser(websocket.CloseInternalServerErr, "proxy unavailable")
		b.finish()
		return
	}
	up.SetReadLimit(appWSMaxMessage)
	b.start(up)
	time.AfterFunc(tshUpgradeLife, func() {
		b.closeBrowser(websocket.CloseGoingAway, "lifetime")
		up.Close()
	})
}
