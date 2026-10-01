//go:build js && wasm

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// An agent connection arrives as a WebSocket on /webapi/connectionupgrade
// with subprotocol alpn-ping. Inside it the agent runs TLS with ALPN
// teleport-reversetunnel, pinned to the cluster host CA, and inside that
// SSH. Only agents with an App or Instance host certificate from the
// cluster host CA get in. The agent opens teleport-heartbeat and pings on
// it, sends keepalive@openssh.com, and reaches auth by opening
// teleport-transport with dial address @remote-auth-server.
const (
	// subprotocol is what a stock agent asks for on reverse tunnel
	// connections (api/client/alpn.go).
	subprotocol       = "alpn-ping"
	alpnReverseTunnel = "teleport-reversetunnel"
	// authDeadline closes a connection that has not authenticated by then.
	// Without it an unauthenticated client can hold a tunnel open forever.
	authDeadline = 30 * time.Second
	// maxConnections is the number of authenticated tunnels the hub
	// accepts. One app service uses about three: its auth client, its
	// tunnel, and a short-lived probe.
	maxConnections = 16
	// maxUnauthenticated is the number of tunnels that have not
	// authenticated, which do not count toward maxConnections. A new one
	// above this closes the oldest tunnel of the client address with the
	// most waiting, so clients that never authenticate cannot keep a
	// redialing agent out.
	maxUnauthenticated = 8

	chanHeartbeat   = "teleport-heartbeat"
	chanTransport   = "teleport-transport"
	chanDiscovery   = "teleport-discovery"
	reqDiscovery    = "discovery"
	reqDial         = "teleport-transport-dial"
	reqPing         = "ping"
	globalKeepalive = "keepalive@openssh.com"
	addrRemoteAuth  = "@remote-auth-server"
	addrLocalNode   = "@local-node"
	extRole         = "x-teleport-role"
	extAuthority    = "x-teleport-authority"
	roleApp         = "App"
	// roleInstance is the app service's process identity, used by its auth
	// client, which reaches auth through the @remote-auth-server
	// passthrough.
	roleInstance = "Instance"

	// discoveryEvery is how often the hub announces itself. The agent
	// forgets a proxy 3 minutes after the last announcement
	// (lib/reversetunnel/track, DefaultProxyExpiry) and then dials to find
	// more, so this stays well under that.
	discoveryEvery = 30 * time.Second
	// maxAuthTries is the number of rejected auth attempts after which the
	// connection is dropped.
	maxAuthTries = 3
	// authRejectDelay is the pause after each rejected attempt, so failing
	// auth is not a free CPU loop.
	authRejectDelay = time.Second
	// maxPendingTransports is the number of transport channels one
	// connection may hold before their dial request.
	maxPendingTransports = 16
	// dialDeadline is how long an agent-opened transport channel may wait
	// for its dial request.
	dialDeadline = 10 * time.Second
	// Passthroughs to auth per connection, and across the hub. Each one
	// holds an auth pipe stream, so the total stays under the pool size to
	// leave streams for the hub's own calls.
	maxPassthroughsPerConn = 2
	maxPassthroughsTotal   = 4
)

// appTunnel is an authenticated App connection and the agent's host ID,
// which is the server_id of a dial into it.
type appTunnel struct {
	conn     *ssh.ServerConn
	serverID string
}

// acceptTunnel accepts an agent's WebSocket and runs TLS and SSH in it.
func (h *hub) acceptTunnel(req *request) *response {
	found := false
	for _, p := range strings.Split(req.header["sec-websocket-protocol"], ",") {
		if strings.TrimSpace(p) == subprotocol {
			found = true
		}
	}
	if !found {
		return textError("unsupported subprotocol", 400)
	}
	if err := h.cfg.err("HUB_TLS_CERT", "HUB_TLS_KEY", "HUB_SSH_KEY", "HUB_SSH_CERT", "HOST_CA_SSH"); err != nil {
		logf("tunnel: %v", err)
		return textError(err.Error(), 500)
	}
	if h.tunnels.Load()-int64(h.unauthenticated.waiting()) >= maxConnections {
		logf("tunnel: connection limit reached")
		return textError("too many connections", 503)
	}
	h.tunnels.Add(1)
	c := acceptWS()
	t, evicted := h.unauthenticated.admit(maxUnauthenticated, clientKey(req), func() {
		logf("tunnel: closed for a newer connection that is not authenticated")
		c.CloseWith(1008, "auth timeout")
	})
	if evicted {
		logf("tunnel: %d connections not authenticated, closed the busiest client's oldest", maxUnauthenticated)
	}
	go func() {
		defer h.tunnels.Add(-1)
		defer c.Close()
		defer t.drop()
		if err := h.serveTunnel(c, t); err != nil {
			logf("tunnel: %v", err)
		}
	}()
	res := &response{status: 101, ws: c}
	return res.add("sec-websocket-protocol", subprotocol)
}

// serveTunnel runs TLS and then the reverse tunnel SSH server on c. It
// drops t, the connection's place among the tunnels that have not
// authenticated, once the agent has.
func (h *hub) serveTunnel(c *wsConn, t *ticket) error {
	var authed atomic.Bool
	deadline := time.AfterFunc(authDeadline, func() {
		if !authed.Load() {
			logf("tunnel: not authenticated after %v, closing", authDeadline)
			c.CloseWith(1008, "auth timeout")
		}
	})
	defer deadline.Stop()

	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*h.cfg.tlsCert},
		NextProtos:   []string{alpnReverseTunnel},
	})
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("tls accept: %w", err)
	}
	logf("tunnel: tls established, alpn %q", tc.ConnectionState().NegotiatedProtocol)

	a := &agent{h: h, pending: make(map[ssh.Channel]bool)}
	cfg := &ssh.ServerConfig{
		MaxAuthTries:      maxAuthTries,
		PublicKeyCallback: a.auth,
	}
	cfg.AddHostKey(h.cfg.sshSigner)
	sc, chans, reqs, err := ssh.NewServerConn(tc, cfg)
	if err != nil {
		return fmt.Errorf("ssh handshake: %w", err)
	}
	authed.Store(true)
	deadline.Stop()
	t.drop()
	a.conn = sc
	a.hostID = sc.Permissions.Extensions["host"]
	a.role = sc.Permissions.Extensions["role"]
	defer a.closed()

	go func() {
		for r := range reqs {
			if r.WantReply {
				r.Reply(r.Type == globalKeepalive, nil)
			}
		}
	}()
	for nc := range chans {
		a.channel(nc)
	}
	logf("tunnel: ssh session ended")
	return nil
}

// agent is the state of one authenticated agent SSH connection.
type agent struct {
	h      *hub
	conn   *ssh.ServerConn
	hostID string
	role   string

	passthroughs atomic.Int64

	mu      sync.Mutex
	pending map[ssh.Channel]bool
	pinged  bool
}

// auth accepts only a host certificate from the cluster host CA, for this
// cluster, with the SSH user as a principal and role App or Instance.
func (a *agent) auth(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	user := meta.User()
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		logf("ssh: rejected plain key for %q", user)
		time.Sleep(authRejectDelay)
		return nil, errors.New("certificate required")
	}
	if reason := a.rejectReason(user, cert); reason != "" {
		logf("ssh: rejected certificate for %q: %s", user, reason)
		time.Sleep(authRejectDelay)
		return nil, errors.New("certificate rejected")
	}
	role := cert.Extensions[extRole]
	logf("ssh: agent %q authenticated, role %s", user, role)
	return &ssh.Permissions{Extensions: map[string]string{"host": user, "role": role}}, nil
}

// rejectReason returns why a certificate is not an acceptable agent
// credential, or "" if it is.
func (a *agent) rejectReason(user string, cert *ssh.Certificate) string {
	cfg := a.h.cfg
	if cert.CertType != ssh.HostCert {
		return "not a host certificate"
	}
	// CertChecker treats an empty principal list as "any principal". The
	// SSH user must be one of them.
	found := false
	for _, p := range cert.ValidPrincipals {
		if p == user {
			found = true
		}
	}
	if !found {
		return "user is not a certificate principal"
	}
	if len(cert.CriticalOptions) != 0 {
		return "unexpected critical options"
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), cfg.hostCA.Marshal()) {
		return "not signed by the cluster host CA"
	}
	// CheckCert checks the validity window and the CA's signature.
	if err := (&ssh.CertChecker{}).CheckCert(user, cert); err != nil {
		return err.Error()
	}
	if got := cert.Extensions[extAuthority]; got != cfg.cluster {
		return fmt.Sprintf("authority %q, want %q", got, cfg.cluster)
	}
	// Go's proxy accepts any system role because proxies and nodes dial in
	// too. This hub has one legitimate client, the app service, which dials
	// with its App identity for the tunnel and its Instance identity for
	// its auth client. Accepting Proxy would let the hub's own identity
	// authenticate to itself.
	switch r := cert.Extensions[extRole]; r {
	case roleApp, roleInstance:
		return ""
	default:
		return fmt.Sprintf("role %q, want %q or %q", r, roleApp, roleInstance)
	}
}

// channel handles one channel the agent opens.
func (a *agent) channel(nc ssh.NewChannel) {
	switch typ := nc.ChannelType(); {
	case typ == chanHeartbeat && a.role == roleApp:
		ch, reqs, err := nc.Accept()
		if err != nil {
			return
		}
		logf("ssh: heartbeat channel accepted")
		go a.heartbeat(ch, reqs)
	case typ == chanTransport:
		a.mu.Lock()
		n := len(a.pending)
		a.mu.Unlock()
		if n >= maxPendingTransports {
			logf("ssh: rejected transport, %d pending", n)
			nc.Reject(ssh.ResourceShortage, "too many pending transports")
			return
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			return
		}
		a.mu.Lock()
		a.pending[ch] = true
		a.mu.Unlock()
		go a.transport(ch, reqs)
	default:
		logf("ssh: rejected channel type %q", typ)
		nc.Reject(ssh.UnknownChannelType, "unknown channel type")
	}
}

// heartbeat answers pings. The first ping registers an App connection as
// the tunnel the hub dials apps through, and starts discovery.
func (a *agent) heartbeat(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	go io.Copy(io.Discard, ch)
	for r := range reqs {
		if r.Type != reqPing {
			logf("ssh: unhandled channel request %q", r.Type)
			r.Reply(false, nil)
			continue
		}
		r.Reply(true, nil)
		a.mu.Lock()
		first := !a.pinged
		a.pinged = true
		a.mu.Unlock()
		if !first {
			continue
		}
		logf("ssh: first ping %q", r.Payload)
		t := &appTunnel{conn: a.conn, serverID: a.hostID}
		a.h.appMu.Lock()
		a.h.appTunnel = t
		a.h.appMu.Unlock()
		go testDial(t)
		go a.discovery()
	}
}

// closed unregisters this connection's app tunnel when the connection
// ends.
func (a *agent) closed() {
	a.conn.Close()
	a.h.appMu.Lock()
	if a.h.appTunnel != nil && a.h.appTunnel.conn == a.conn {
		a.h.appTunnel = nil
	}
	a.h.appMu.Unlock()
}

// transport waits for the dial request on an agent-opened transport
// channel. The only address the hub accepts is @remote-auth-server, and
// the bytes are the agent's own mTLS to auth, which the hub only copies
// to an auth pipe stream.
func (a *agent) transport(ch ssh.Channel, reqs <-chan *ssh.Request) {
	done := func() {
		a.mu.Lock()
		delete(a.pending, ch)
		a.mu.Unlock()
	}
	timer := time.NewTimer(dialDeadline)
	defer timer.Stop()
	var r *ssh.Request
	for r == nil {
		select {
		case <-timer.C:
			logf("ssh: transport channel never dialed, closing")
			done()
			ch.Close()
			return
		case got, ok := <-reqs:
			if !ok {
				done()
				ch.Close()
				return
			}
			if got.Type != reqDial {
				logf("ssh: unhandled channel request %q", got.Type)
				got.Reply(false, nil)
				continue
			}
			r = got
		}
	}
	done()
	go ssh.DiscardRequests(reqs)
	refuse := func(format string, args ...any) {
		logf(format, args...)
		r.Reply(false, nil)
		ch.Close()
	}
	var dial struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(r.Payload, &dial); err != nil {
		refuse("ssh: bad dial request: %v", err)
		return
	}
	if dial.Address != addrRemoteAuth {
		refuse("ssh: rejected dial to %q", dial.Address)
		return
	}
	if a.passthroughs.Load() >= maxPassthroughsPerConn || a.h.passthroughs.Load() >= maxPassthroughsTotal {
		refuse("ssh: passthrough limit reached")
		return
	}
	pipe := a.h.pool.take()
	if pipe == nil {
		refuse("ssh: passthrough refused, no auth pipe stream")
		return
	}
	r.Reply(true, nil)
	logf("ssh: passthrough to auth over the callout")
	a.passthroughs.Add(1)
	a.h.passthroughs.Add(1)
	defer a.passthroughs.Add(-1)
	defer a.h.passthroughs.Add(-1)
	up, down := splice(ch, pipe)
	logf("ssh: passthrough closed, %d up, %d down", up, down)
}

// splice copies both ways between an SSH channel and a pipe stream until
// either side ends, then closes both. It returns the bytes copied from the
// channel and to it.
func splice(ch ssh.Channel, pipe io.ReadWriteCloser) (up, down int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		down, _ = io.Copy(ch, pipe)
		ch.CloseWrite()
		ch.Close()
	}()
	up, _ = io.Copy(pipe, ch)
	pipe.Close()
	wg.Wait()
	return up, down
}

// discovery announces this hub every discoveryEvery until the connection
// closes.
func (a *agent) discovery() {
	ch, reqs, err := a.conn.OpenChannel(chanDiscovery, nil)
	if err != nil {
		logf("ssh: discovery open failed: %v", err)
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)
	go io.Copy(io.Discard, ch)
	payload, _ := json.Marshal(map[string]any{
		"proxies": []any{map[string]any{
			"version":  "v2",
			"metadata": map[string]string{"name": a.h.cfg.proxyName},
		}},
	})
	for {
		if _, err := ch.SendRequest(reqDiscovery, false, payload); err != nil {
			logf("ssh: discovery failed: %v", err)
			break
		}
		a.h.lastDiscovery.Store(time.Now().UnixMilli())
		time.Sleep(discoveryEvery)
	}
	logf("ssh: discovery loop ended")
}

// testDial opens a transport channel into the agent and asks it to dial
// its local app service, which is how the hub reaches apps. It only checks
// that the agent accepts the dial.
func testDial(t *appTunnel) {
	ch, err := t.dial()
	if err != nil {
		logf("ssh: test dial: %v", err)
		return
	}
	logf("ssh: test dial into agent accepted: true")
	ch.Close()
}

// dial opens a transport channel into the agent and asks it to dial its
// local app service.
func (t *appTunnel) dial() (ssh.Channel, error) {
	ch, reqs, err := t.conn.OpenChannel(chanTransport, nil)
	if err != nil {
		return nil, fmt.Errorf("transport open: %w", err)
	}
	go ssh.DiscardRequests(reqs)
	payload, _ := json.Marshal(map[string]string{
		"address":   addrLocalNode,
		"server_id": t.serverID,
		"conn_type": "app",
	})
	ok, err := ch.SendRequest(reqDial, true, payload)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("dial request: %w", err)
	}
	if !ok {
		ch.Close()
		return nil, errors.New("dial refused by agent")
	}
	return ch, nil
}
