package conformance

import (
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ProxyWebHost is the host of the fake home proxy's public_addr, and
// ProxyWebAddr the address the hub sends as Host.
const (
	ProxyWebHost = "proxy.hub.test"
	ProxyWebAddr = ProxyWebHost + ":3080"
)

// ProxySeen is one request the fake home proxy got.
type ProxySeen struct {
	Method, Path, Host string
	Header             http.Header
	Body               string
}

// ProxyWeb is the home proxy's web listener on the tsh path. It serves
// TLS with a certificate for ProxyWebHost from the cluster TLS CA, which
// the tests give the hub as PROXY_WEB_CA. It answers ping and the
// passwordless login routes with canned JSON, and on the connection
// upgrade echoes each binary message back.
type ProxyWeb struct {
	ln   *connListener
	mu   sync.Mutex
	seen []ProxySeen
}

// NewProxyWeb starts a fake home proxy that signs its certificate with p.
func NewProxyWeb(p *PKI) (*ProxyWeb, error) {
	cert, err := p.TLSLeaf(ProxyWebHost, ProxyWebHost)
	if err != nil {
		return nil, err
	}
	w := &ProxyWeb{ln: newConnListener()}
	srv := &http.Server{Handler: http.HandlerFunc(w.serve), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(tls.NewListener(w.ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}))
	return w, nil
}

// Close stops the fake home proxy.
func (w *ProxyWeb) Close() { w.ln.Close() }

// Seen returns the requests the fake home proxy got so far.
func (w *ProxyWeb) Seen() []ProxySeen {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]ProxySeen(nil), w.seen...)
}

// PingAnswer is the ping answer of the fake home proxy, with the proxy's
// own LAN-only addresses in it.
const PingAnswer = `{"auth":{"type":"local","second_factor":"on"},` +
	`"proxy":{"ssh":{"listen_addr":"0.0.0.0:3023","web_listen_addr":"0.0.0.0:3080",` +
	`"public_addr":"` + ProxyWebAddr + `","ssh_public_addr":"` + ProxyWebHost + `:3023"},` +
	`"kube":{"enabled":false,"public_addr":"` + ProxyWebHost + `:3026"},"tls_routing_enabled":true},` +
	`"server_version":"18.11.1","cluster_name":"home"}`

func (w *ProxyWeb) serve(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.mu.Lock()
	w.seen = append(w.seen, ProxySeen{Method: r.Method, Path: r.URL.Path, Host: r.Host, Header: r.Header.Clone(), Body: string(body)})
	w.mu.Unlock()
	switch r.URL.Path {
	case "/webapi/ping", "/webapi/ping/passwordless":
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, PingAnswer)
	case "/webapi/mfa/login/begin", "/webapi/mfa/login/finish":
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"path":"`+r.URL.Path+`","body":`+string(body)+`}`)
	case "/webapi/connectionupgrade":
		u := websocket.Upgrader{Subprotocols: []string{"alpn-ping", "alpn"}}
		ws, err := u.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			typ, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if ws.WriteMessage(typ, msg) != nil {
				return
			}
		}
	default:
		http.NotFound(rw, r)
	}
}
