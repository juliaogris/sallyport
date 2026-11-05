package conformance

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/juliaogris/sallyport/conformance/testapp"
)

// tshStack is a lazy stack whose hub has the tsh path on for tp, with a
// fake home proxy behind the fake auth's proxy streams.
type tshStack struct {
	*stack
	proxy *ProxyWeb
}

func newTshStack(t *testing.T, mode string) *tshStack {
	t.Helper()
	vars := BaseVars()
	vars["APPS"] = "bench,tp:/web"
	vars["SUB_APPS"] = "tp"
	vars["WEB_UI_APPS"] = "tp"
	vars["PROXY_WEB_ADDR"] = ProxyWebAddr
	if mode == "lazy" {
		vars["HUB_MODE"] = "lazy"
	}
	secrets := pki.Secrets()
	secrets["PROXY_WEB_CA"] = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.TLSCA.Raw}))

	dir := filepath.Join(tmp, t.Name())
	require.NoError(t, os.MkdirAll(dir, 0o700))
	h, err := StartHub(t.Context(), hubDir, dir, vars, secrets)
	require.NoError(t, err)
	t.Cleanup(h.Stop)
	logOnFailure(t, h)

	auth, err := NewFakeAuth(pki)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	proxy, err := NewProxyWeb(pki)
	require.NoError(t, err)
	t.Cleanup(proxy.Close)
	auth.SetProxyWeb(proxy)
	if mode == "lazy" {
		app, err := NewAppServer(pki, testapp.Handler(""))
		require.NoError(t, err)
		t.Cleanup(app.Close)
		auth.RunLazy(t.Context(), h, app)
		require.True(t, h.WaitLog(controlVerified, 1, 20*time.Second), "no control socket verified")
	}
	return &tshStack{stack: &stack{hub: h, auth: auth, sub: subApps(vars)}, proxy: proxy}
}

// tshGet sends a GET as tsh does: no cookie, no Origin.
func (s *tshStack) tshDo(t *testing.T, method, path, body string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+subAppHost("tp")+path, strings.NewReader(body))
	require.NoError(t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := s.hub.Do(req)
	require.NoError(t, err)
	return resp
}

// innerHello returns the bytes of a ClientHello for the home cluster with
// the given ALPN protocols and server name.
func innerHello(t *testing.T, sni string, protos ...string) []byte {
	t.Helper()
	c, srv := net.Pipe()
	defer srv.Close()
	go func() {
		tls.Client(c, &tls.Config{ServerName: sni, NextProtos: protos}).Handshake()
		c.Close()
	}()
	require.NoError(t, srv.SetReadDeadline(time.Now().Add(5*time.Second)))
	// The first record holds the whole ClientHello for these sizes.
	head := make([]byte, 5)
	_, err := ioReadFull(srv, head)
	require.NoError(t, err)
	n := int(head[3])<<8 | int(head[4])
	rest := make([]byte, n)
	_, err = ioReadFull(srv, rest)
	require.NoError(t, err)
	return append(head, rest...)
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func clusterSNI() string { return hex.EncodeToString([]byte(pki.Cluster)) + "." + authSNI }

func (s *tshStack) dialUpgrade(t *testing.T, protocol string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	d := websocket.Dialer{
		NetDialContext:   s.hub.DialContext,
		TLSClientConfig:  EdgeTLS(),
		HandshakeTimeout: 20 * time.Second,
		Subprotocols:     []string{protocol},
	}
	return d.Dial("wss://"+subAppHost("tp")+"/webapi/connectionupgrade", http.Header{"Cf-Connecting-Ip": {randomIP()}})
}

// upgrades returns how many connection upgrades reached the proxy.
func (s *tshStack) upgrades() int {
	n := 0
	for _, r := range s.proxy.Seen() {
		if r.Path == "/webapi/connectionupgrade" {
			n++
		}
	}
	return n
}

// TestTshPath checks the tsh path on the host of a web UI app: that the
// allowlisted requests with no hub cookie reach the home proxy on proxy
// streams with the ping rewritten and the client's credentials and
// forwarding headers dropped, that everything else still goes to login,
// and that the connection upgrade carries only a ClientHello the gate
// allows.
func TestTshPath(t *testing.T) {
	s := newTshStack(t, "lazy")

	t.Run("ping is rewritten", func(t *testing.T) {
		resp := s.tshDo(t, "GET", "/webapi/ping/passwordless?UpdateGroup=g", "", nil)
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		var doc struct {
			Proxy struct {
				SSH  map[string]any `json:"ssh"`
				Kube map[string]any `json:"kube"`
				TLS  bool           `json:"tls_routing_enabled"`
			} `json:"proxy"`
			Cluster string `json:"cluster_name"`
		}
		require.NoError(t, json.Unmarshal(body, &doc))
		require.Equal(t, map[string]any{"public_addr": subAppHost("tp") + ":443"}, doc.Proxy.SSH)
		require.Equal(t, map[string]any{"enabled": false}, doc.Proxy.Kube)
		require.True(t, doc.Proxy.TLS)
		require.Equal(t, "home", doc.Cluster)
		require.NotContains(t, string(body), ProxyWebHost)
	})

	t.Run("headers", func(t *testing.T) {
		before := len(s.proxy.Seen())
		resp := s.tshDo(t, "POST", "/webapi/mfa/login/begin", `{"passwordless":true}`, http.Header{
			"Content-Type":     {"application/json"},
			"Cf-Connecting-Ip": {"203.0.113.7"},
			"X-Forwarded-For":  {"198.51.100.1"},
			"X-Forwarded-Host": {"evil"},
			"Forwarded":        {"for=198.51.100.1"},
			"X-Real-Ip":        {"198.51.100.1"},
			"Authorization":    {"Bearer stolen"},
			"Cookie":           {"__Host-session=x; other=y"},
		})
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		require.JSONEq(t, `{"path":"/webapi/mfa/login/begin","body":{"passwordless":true}}`, string(body))
		seen := s.proxy.Seen()
		require.Len(t, seen, before+1)
		r := seen[len(seen)-1]
		require.Equal(t, ProxyWebAddr, r.Host)
		require.Equal(t, []string{"203.0.113.7"}, r.Header.Values("X-Forwarded-For"))
		for _, name := range []string{"X-Forwarded-Host", "Forwarded", "X-Real-Ip", "Authorization", "Cookie", "Origin"} {
			require.Empty(t, r.Header.Values(name), name)
		}
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
	})

	t.Run("finish", func(t *testing.T) {
		resp := s.tshDo(t, "POST", "/webapi/mfa/login/finish", `{"x":1}`, http.Header{"Content-Type": {"application/json"}})
		body := readBody(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		require.JSONEq(t, `{"path":"/webapi/mfa/login/finish","body":{"x":1}}`, string(body))
	})

	t.Run("cross-site post", func(t *testing.T) {
		before := len(s.proxy.Seen())
		resp := s.tshDo(t, "POST", "/webapi/mfa/login/begin", `{}`, http.Header{"Origin": {"https://evil.example"}})
		readBody(t, resp)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		resp = s.tshDo(t, "POST", "/webapi/mfa/login/begin", `{}`, http.Header{"Sec-Fetch-Site": {"cross-site"}})
		readBody(t, resp)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Len(t, s.proxy.Seen(), before)
	})

	t.Run("near misses go to login", func(t *testing.T) {
		before := len(s.proxy.Seen())
		for _, c := range []struct{ method, path string }{
			{"GET", "/webapi/pingx"},
			{"GET", "/webapi/ping/"},
			{"GET", "/webapi/ping/local"},
			{"GET", "/webapi/ping%2Fpasswordless"},
			{"GET", "//webapi/ping"},
			{"GET", "/v1/webapi/ping"},
			{"GET", "/webapi/ping/../sites"},
			{"GET", "/webapi/sites"},
			{"GET", "/webapi/find"},
			{"GET", "/web"},
			{"HEAD", "/webapi/ping"},
			{"POST", "/webapi/ping"},
			{"GET", "/webapi/mfa/login/begin"},
			{"POST", "/webapi/sessions/web"},
			{"GET", "/webapi/connectionupgrade"},
		} {
			resp := s.tshDo(t, c.method, c.path, "", nil)
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode, "%s %s", c.method, c.path)
		}
		require.Len(t, s.proxy.Seen(), before)
	})

	t.Run("one cookie goes to login", func(t *testing.T) {
		before := len(s.proxy.Seen())
		for _, name := range []string{"__Host-sp_app", "__Host-sp_subject"} {
			resp := s.tshDo(t, "GET", "/webapi/ping/passwordless", "", http.Header{"Cookie": {name + "=x"}})
			readBody(t, resp)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode, name)
		}
		require.Len(t, s.proxy.Seen(), before)
	})

	t.Run("upgrade passes an allowed hello", func(t *testing.T) {
		for _, protos := range [][]string{
			{"teleport-proxy-ssh-grpc", "h2"},
			{"teleport-auth@" + clusterSNI(), "h2"},
		} {
			ws, resp, err := s.dialUpgrade(t, "alpn-ping")
			require.NoError(t, err, protos)
			require.Equal(t, "alpn-ping", resp.Header.Get("Sec-WebSocket-Protocol"))
			hello := innerHello(t, clusterSNI(), protos...)
			// Split the hello across two messages, as the gate must
			// reassemble it.
			require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, hello[:20]))
			require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, hello[20:]))
			require.NoError(t, ws.SetReadDeadline(time.Now().Add(20*time.Second)))
			var got []byte
			for len(got) < len(hello) {
				typ, msg, err := ws.ReadMessage()
				require.NoError(t, err, protos)
				require.Equal(t, websocket.BinaryMessage, typ)
				got = append(got, msg...)
			}
			require.True(t, bytes.Equal(hello, got), protos)

			// Bytes after the hello cross too, 4 MiB each way.
			big := bytes.Repeat([]byte("x"), 1<<20)
			go func() {
				for range 4 {
					ws.WriteMessage(websocket.BinaryMessage, big)
				}
			}()
			n := 0
			for n < 4<<20 {
				_, msg, err := ws.ReadMessage()
				require.NoError(t, err)
				n += len(msg)
			}
			require.Equal(t, 4<<20, n)
			ws.Close()
		}
	})

	t.Run("upgrade refuses other hellos", func(t *testing.T) {
		before := s.upgrades()
		for name, hello := range map[string][]byte{
			"h2 first":     innerHello(t, clusterSNI(), "h2", "teleport-proxy-ssh-grpc"),
			"http/1.1":     innerHello(t, clusterSNI(), "http/1.1"),
			"join service": innerHello(t, clusterSNI(), "teleport-proxy-grpc", "h2"),
			"no alpn":      innerHello(t, clusterSNI()),
			"wrong sni":    innerHello(t, ProxyWebHost, "teleport-proxy-ssh-grpc"),
			"mixed":        innerHello(t, clusterSNI(), "teleport-proxy-ssh-grpc", "http/1.1"),
			"not tls":      []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		} {
			ws, _, err := s.dialUpgrade(t, "alpn")
			require.NoError(t, err, name)
			require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, hello), name)
			require.NoError(t, ws.SetReadDeadline(time.Now().Add(20*time.Second)))
			_, _, err = ws.ReadMessage()
			require.True(t, websocket.IsCloseError(err, websocket.ClosePolicyViolation), "%s: %v", name, err)
			ws.Close()
		}
		require.Equal(t, before, s.upgrades())
	})

	t.Run("upgrade without a subprotocol goes to login", func(t *testing.T) {
		_, resp, err := s.dialUpgrade(t, "chat")
		require.Error(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	})
}

// TestTshPathTunnelMode checks that a hub in tunnel mode keeps the tsh
// path off and sends tsh to login.
func TestTshPathTunnelMode(t *testing.T) {
	s := newTshStack(t, "tunnel")
	resp := s.tshDo(t, "GET", "/webapi/ping/passwordless", "", nil)
	readBody(t, resp)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Empty(t, s.proxy.Seen())
}
