package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// helloBytes returns the ClientHello that crypto/tls sends for sni and alpn.
func helloBytes(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		tc := tls.Client(c, &tls.Config{ServerName: sni, NextProtos: alpn})
		tc.SetDeadline(time.Now().Add(2 * time.Second))
		tc.Handshake()
		c.Close()
	}()
	var buf bytes.Buffer
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	_, err := io.ReadFull(s, hdr)
	require.NoError(t, err)
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	_, err = io.ReadFull(s, body)
	require.NoError(t, err)
	buf.Write(hdr)
	buf.Write(body)
	return buf.Bytes()
}

func TestParseClientHello(t *testing.T) {
	b := helloBytes(t, "616263.teleport.cluster.local", []string{"teleport-proxy-ssh-grpc", "h2"})

	h, err := parseClientHello(b)
	require.NoError(t, err)
	require.Equal(t, clientHello{sni: "616263.teleport.cluster.local", alpn: []string{"teleport-proxy-ssh-grpc", "h2"}}, h)

	for _, n := range []int{0, 4, 5, 40, len(b) - 1} {
		_, err := parseClientHello(b[:n])
		require.ErrorIs(t, err, errShort, "prefix of %d bytes", n)
	}

	// The same handshake split across two TLS records.
	hs := b[5:]
	split := append(record(hs[:30]), record(hs[30:])...)
	h, err = parseClientHello(split)
	require.NoError(t, err)
	require.Equal(t, []string{"teleport-proxy-ssh-grpc", "h2"}, h.alpn)

	_, err = parseClientHello([]byte{0x17, 3, 3, 0, 1, 0})
	require.ErrorContains(t, err, "not handshake")
}

func record(p []byte) []byte {
	out := []byte{0x16, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(out[3:], uint16(len(p)))
	return append(out, p...)
}

// wsFrame returns one WebSocket frame, masked if key is not nil.
func wsFrame(fin bool, opcode byte, p, key []byte) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	var maskBit byte
	if key != nil {
		maskBit = 0x80
	}
	switch {
	case len(p) < 126:
		out = append(out, maskBit|byte(len(p)))
	case len(p) <= 0xffff:
		out = append(out, maskBit|126, byte(len(p)>>8), byte(len(p)))
	default:
		out = append(out, maskBit|127)
		out = binary.BigEndian.AppendUint64(out, uint64(len(p)))
	}
	if key == nil {
		return append(out, p...)
	}
	out = append(out, key...)
	for i, c := range p {
		out = append(out, c^key[i%4])
	}
	return out
}

func TestFrameTap(t *testing.T) {
	hello := helloBytes(t, "x.teleport.cluster.local", []string{"teleport-proxy-ssh"})
	key := []byte{1, 2, 3, 4}
	var stream []byte
	stream = append(stream, wsFrame(false, 0x2, hello[:20], key)...)
	stream = append(stream, wsFrame(true, 0x0, hello[20:], key)...)
	stream = append(stream, wsFrame(true, 0x9, nil, key)...)
	stream = append(stream, wsFrame(true, 0x2, bytes.Repeat([]byte{7}, 70000), key)...)

	var logs []string
	tap := newFrameTap("client", func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	var payloads int
	tap.payload = func(byte, []byte) { payloads++ }
	// Feed the stream in small pieces, as io.Copy might.
	for i := 0; i < len(stream); i += 7 {
		n, err := tap.Write(stream[i:min(i+7, len(stream))])
		require.NoError(t, err)
		require.Equal(t, min(7, len(stream)-i), n)
	}
	require.Equal(t, 4, payloads)
	require.Equal(t, 1, tap.pings)
	require.Equal(t, []string{
		`client hello: sni "x.teleport.cluster.local" alpn ["teleport-proxy-ssh"]`,
		"client sent ping 1",
	}, logs)
	require.Empty(t, tap.buf)
}

func TestRewritePing(t *testing.T) {
	in := `{"auth":{"type":"local"},"proxy":{"kube":{"enabled":true,"public_addr":"k:3026","listen_addr":"0.0.0.0:3026"},` +
		`"ssh":{"listen_addr":"0.0.0.0:3023","tunnel_listen_addr":"0.0.0.0:3024","web_listen_addr":"0.0.0.0:3080",` +
		`"public_addr":"proxy.lan.test:3780","ssh_public_addr":"proxy.lan.test:3023","ssh_tunnel_public_addr":"proxy.lan.test:3024"},` +
		`"db":{"postgres_public_addr":"p:5432","mysql_listen_addr":"0.0.0.0:3036"},"tls_routing_enabled":true},"server_version":"18.11.1"}`
	out, err := rewritePing([]byte(in), "relay.test:18443")
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	want := map[string]any{
		"auth": map[string]any{"type": "local"},
		"proxy": map[string]any{
			"kube":                map[string]any{"enabled": true},
			"ssh":                 map[string]any{"public_addr": "relay.test:18443"},
			"db":                  map[string]any{},
			"tls_routing_enabled": true,
		},
		"server_version": "18.11.1",
	}
	require.Equal(t, want, got)

	_, err = rewritePing([]byte(`{"auth":{}}`), "relay.test:18443")
	require.ErrorContains(t, err, "no proxy object")
}

// testPKI is a test CA and a leaf certificate it issued for one name.
type testPKI struct {
	roots *tlsRoots
	leaf  tls.Certificate
}

func newTestPKI(t *testing.T, name string) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testPKI{
		roots: &tlsRoots{p: pool},
		leaf:  tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey},
	}
}

// fakeProxy is a stand-in for the proxy's web listener. It answers ping,
// records each request, and on /webapi/connectionupgrade switches
// protocols and echoes the bytes it gets.
type fakeProxy struct {
	mu   sync.Mutex
	reqs []string
	srv  *httptest.Server
}

func newFakeProxy(t *testing.T, cert tls.Certificate) *fakeProxy {
	t.Helper()
	p := &fakeProxy{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.reqs = append(p.reqs, fmt.Sprintf("%s %s host=%s xff=%q", r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("X-Forwarded-For")))
		p.mu.Unlock()
		switch r.URL.Path {
		case "/webapi/ping/passwordless":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"proxy":{"ssh":{"public_addr":"proxy.lan.test:3780"},"tls_routing_enabled":true}}`)
		case "/webapi/connectionupgrade":
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: %s\r\n\r\n", r.Header.Get("Sec-WebSocket-Protocol"))
			buf.Flush()
			io.Copy(conn, buf)
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	p.srv = srv
	return p
}

func (p *fakeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.reqs...)
}

// startRelay serves a relay over plain HTTP, since the relay's own TLS is
// ListenAndServeTLS and not what these tests check.
func startRelay(t *testing.T, upstream string, roots *tlsRoots) *httptest.Server {
	t.Helper()
	r, err := newRelay("relay.test:18443", upstream, "proxy.lan.test:3780", roots)
	require.NoError(t, err)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestRelayPing(t *testing.T) {
	pki := newTestPKI(t, "proxy.lan.test")
	p := newFakeProxy(t, pki.leaf)
	relay := startRelay(t, p.srv.Listener.Addr().String(), pki.roots)

	req, _ := http.NewRequest("GET", relay.URL+"/webapi/ping/passwordless?UpdateGroup=x", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.JSONEq(t, `{"proxy":{"ssh":{"public_addr":"relay.test:18443"},"tls_routing_enabled":true}}`, string(body))
	require.Equal(t, []string{`GET /webapi/ping/passwordless?UpdateGroup=x host=proxy.lan.test:3780 xff=""`}, p.requests())
}

func TestRelayRefusesUntrustedUpstream(t *testing.T) {
	trusted := newTestPKI(t, "proxy.lan.test")
	other := newTestPKI(t, "proxy.lan.test")
	wrongName := newTestPKI(t, "other.test")
	for name, cert := range map[string]tls.Certificate{"other root": other.leaf, "wrong name": wrongName.leaf} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProxy(t, cert)
			roots := trusted.roots
			if name == "wrong name" {
				roots = wrongName.roots
			}
			relay := startRelay(t, p.srv.Listener.Addr().String(), roots)

			resp, err := http.Get(relay.URL + "/webapi/ping/passwordless")
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusBadGateway, resp.StatusCode)

			status, _ := upgrade(t, relay.Listener.Addr().String(), "alpn-ping")
			require.Equal(t, http.StatusBadGateway, status)
			require.Empty(t, p.requests())
		})
	}
}

// upgrade sends a WebSocket upgrade for /webapi/connectionupgrade and
// returns the status and, on 101, the connection and its reader.
func upgrade(t *testing.T, addr, proto string) (int, *upgraded) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	fmt.Fprintf(c, "GET /webapi/connectionupgrade HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: %s\r\n\r\n", proto)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return resp.StatusCode, nil
	}
	require.Equal(t, proto, resp.Header.Get("Sec-WebSocket-Protocol"))
	t.Cleanup(func() { c.Close() })
	return resp.StatusCode, &upgraded{c: c, r: br}
}

type upgraded struct {
	c net.Conn
	r *bufio.Reader
}

func TestRelayUpgrade(t *testing.T) {
	pki := newTestPKI(t, "proxy.lan.test")
	p := newFakeProxy(t, pki.leaf)
	relay := startRelay(t, p.srv.Listener.Addr().String(), pki.roots)

	for _, proto := range []string{"alpn-ping", "alpn"} {
		t.Run(proto, func(t *testing.T) {
			status, u := upgrade(t, relay.Listener.Addr().String(), proto)
			require.Equal(t, http.StatusSwitchingProtocols, status)

			// The fake proxy echoes, so 1 MiB of frames comes back unchanged.
			hello := helloBytes(t, "x.teleport.cluster.local", []string{"teleport-proxy-ssh-grpc"})
			msg := append(wsFrame(true, 0x2, hello, []byte{9, 8, 7, 6}), wsFrame(true, 0x2, bytes.Repeat([]byte("z"), 1<<20), []byte{1, 1, 1, 1})...)
			go u.c.Write(msg)
			got := make([]byte, len(msg))
			u.c.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, err := io.ReadFull(u.r, got)
			require.NoError(t, err)
			require.Equal(t, msg, got)
		})
	}
	reqs := p.requests()
	require.Len(t, reqs, 2)
	for _, r := range reqs {
		require.True(t, strings.HasPrefix(r, "GET /webapi/connectionupgrade host=proxy.lan.test:3780"), r)
	}
}
