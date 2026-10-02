package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// Tunnel protocol names, as the stock agent uses them.
const (
	TunnelPath        = "/webapi/connectionupgrade"
	TunnelSubprotocol = "alpn-ping"
	ALPNReverseTunnel = "teleport-reversetunnel"
	ChanHeartbeat     = "teleport-heartbeat"
	ChanTransport     = "teleport-transport"
	ChanDiscovery     = "teleport-discovery"
	ReqDial           = "teleport-transport-dial"
	AddrRemoteAuth    = "@remote-auth-server"
	AddrLocalNode     = "@local-node"
)

// Identity is an agent's SSH key and certificate. With a nil Cert the
// agent authenticates with the plain key.
type Identity struct {
	Signer ssh.Signer
	Cert   *ssh.Certificate
	// User is the SSH user the agent dials as.
	User string
}

// NewIdentity generates an agent key and has spec signed by ca.
func (p *PKI) NewIdentity(ca ssh.Signer, user string, spec CertSpec) (*Identity, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	id := &Identity{Signer: signer, User: user}
	if len(spec.Principals) == 0 {
		return id, nil
	}
	if id.Cert, err = p.SignWith(ca, signer.PublicKey(), spec); err != nil {
		return nil, err
	}
	return id, nil
}

// AgentIdentity returns an identity with a valid certificate for role, as
// the app service's App or Instance identity.
func (p *PKI) AgentIdentity(role string) (*Identity, error) {
	uuid := NewUUID()
	user := uuid + "." + p.Cluster
	return p.NewIdentity(p.HostCA, user, CertSpec{Principals: []string{user, uuid}, Role: role})
}

// DialTunnelWS opens the tunnel WebSocket with the subprotocols given.
func (h *Hub) DialTunnelWS(ctx context.Context, subprotocols ...string) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{NetDialContext: h.DialContext, TLSClientConfig: EdgeTLS(), Subprotocols: subprotocols, HandshakeTimeout: 20 * time.Second}
	return d.DialContext(ctx, "wss://"+LoginHost+TunnelPath, nil)
}

// DialTunnelTLS opens the tunnel WebSocket and runs TLS in it, checking
// the hub certificate against the cluster TLS CA.
func (h *Hub) DialTunnelTLS(ctx context.Context, p *PKI) (*tls.Conn, error) {
	ws, _, err := h.DialTunnelWS(ctx, TunnelSubprotocol)
	if err != nil {
		return nil, fmt.Errorf("tunnel websocket: %w", err)
	}
	tc := tls.Client(NewWSConn(ws), &tls.Config{
		ServerName: p.HubHost,
		RootCAs:    p.TLSCAPool,
		NextProtos: []string{ALPNReverseTunnel},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		ws.Close()
		return nil, fmt.Errorf("tunnel tls: %w", err)
	}
	return tc, nil
}

// Agent is a fake app service connected to the hub's reverse tunnel.
type Agent struct {
	Conn ssh.Conn
	// HostCert is the certificate the hub presented.
	HostCert *ssh.Certificate

	// Discovery receives the payload of each discovery request.
	Discovery chan []byte
	// Dials receives the payload of each dial request on a transport
	// channel the hub opens, with the channel.
	Dials chan Dial

	mu     sync.Mutex
	closed bool
	app    *connListener
}

// Dial is a transport channel the hub opened into the agent and the
// payload of its dial request.
type Dial struct {
	Payload []byte
	Channel ssh.Channel
}

// DialAgent connects id to the hub's tunnel. The hub's host key must be a
// host certificate signed by the cluster host CA. Each of opts changes the
// SSH client config before the dial.
func (h *Hub) DialAgent(ctx context.Context, p *PKI, id *Identity, opts ...func(*ssh.ClientConfig)) (*Agent, error) {
	tc, err := h.DialTunnelTLS(ctx, p)
	if err != nil {
		return nil, err
	}
	auth := id.Signer
	if id.Cert != nil {
		if auth, err = ssh.NewCertSigner(id.Cert, id.Signer); err != nil {
			return nil, err
		}
	}
	a := &Agent{
		Discovery: make(chan []byte, 16),
		Dials:     make(chan Dial, 16),
	}
	cfg := &ssh.ClientConfig{
		User: id.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(auth)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return fmt.Errorf("hub host key is a plain %s key, want a host certificate", key.Type())
			}
			if cert.CertType != ssh.HostCert {
				return fmt.Errorf("hub certificate type %d, want host", cert.CertType)
			}
			checker := &ssh.CertChecker{}
			if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil {
				return fmt.Errorf("hub host certificate: %w", err)
			}
			if string(cert.SignatureKey.Marshal()) != string(p.HostCA.PublicKey().Marshal()) {
				return fmt.Errorf("hub host certificate not signed by the cluster host CA")
			}
			a.HostCert = cert
			return nil
		},
		HostKeyAlgorithms: []string{
			ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01,
			ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01,
		},
		Timeout: 20 * time.Second,
	}
	for _, o := range opts {
		o(cfg)
	}
	stop := context.AfterFunc(ctx, func() { tc.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(tc, LoginHost, cfg)
	stop()
	if err != nil {
		tc.Close()
		return nil, err
	}
	a.Conn = sc
	go ssh.DiscardRequests(reqs)
	go a.serve(chans)
	return a, nil
}

func (a *Agent) serve(chans <-chan ssh.NewChannel) {
	for nc := range chans {
		switch nc.ChannelType() {
		case ChanDiscovery:
			ch, reqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go io.Copy(io.Discard, ch)
			go func() {
				for r := range reqs {
					select {
					case a.Discovery <- r.Payload:
					default:
					}
					if r.WantReply {
						r.Reply(true, nil)
					}
				}
			}()
		case ChanTransport:
			ch, reqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go func() {
				for r := range reqs {
					if r.Type != ReqDial {
						r.Reply(false, nil)
						continue
					}
					r.Reply(true, nil)
					go ssh.DiscardRequests(reqs)
					a.mu.Lock()
					app := a.app
					a.mu.Unlock()
					if app != nil {
						if !app.put(newDeadlineConn(chanConn{ch})) {
							ch.Close()
						}
						return
					}
					select {
					case a.Dials <- Dial{Payload: r.Payload, Channel: ch}:
					default:
						ch.Close()
					}
					return
				}
			}()
		default:
			nc.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// ServeApp makes the agent serve handler on every dial the hub makes into
// it, as the app service does: TLS with a certificate for the cluster's
// app SNI, a client certificate from the cluster TLS CA required, then
// HTTP/1.1. Dials no longer go to Dials.
func (a *Agent) ServeApp(p *PKI, handler http.Handler) error {
	sni := hex.EncodeToString([]byte(p.Cluster)) + "." + authSNI
	cert, err := p.TLSLeaf(sni, sni)
	if err != nil {
		return err
	}
	ln := newConnListener()
	srv := &http.Server{Handler: handler}
	go srv.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.TLSCAPool,
	}))
	a.mu.Lock()
	a.app = ln
	a.mu.Unlock()
	return nil
}

// Heartbeat opens the heartbeat channel and sends one ping. It returns
// the channel and the ping's reply.
func (a *Agent) Heartbeat() (ssh.Channel, bool, error) {
	ch, reqs, err := a.Conn.OpenChannel(ChanHeartbeat, nil)
	if err != nil {
		return nil, false, err
	}
	go ssh.DiscardRequests(reqs)
	ok, err := ch.SendRequest("ping", true, []byte("conformance"))
	return ch, ok, err
}

// OpenTransport opens a transport channel and sends a dial request for
// addr. It returns the channel and the dial's reply.
func (a *Agent) OpenTransport(addr string) (ssh.Channel, bool, error) {
	ch, reqs, err := a.Conn.OpenChannel(ChanTransport, nil)
	if err != nil {
		return nil, false, err
	}
	go ssh.DiscardRequests(reqs)
	payload, _ := json.Marshal(map[string]string{"address": addr})
	ok, err := ch.SendRequest(ReqDial, true, payload)
	return ch, ok, err
}

// Close closes the SSH connection.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.app != nil {
		a.app.Close()
	}
	return a.Conn.Close()
}

// chanConn is a net.Conn over an SSH channel.
type chanConn struct{ ssh.Channel }

func (chanConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (chanConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (chanConn) SetDeadline(time.Time) error      { return nil }
func (chanConn) SetReadDeadline(time.Time) error  { return nil }
func (chanConn) SetWriteDeadline(time.Time) error { return nil }

// WithRekeyThreshold makes the agent start a key exchange after every n
// bytes it sends or receives.
func WithRekeyThreshold(n uint64) func(*ssh.ClientConfig) {
	return func(c *ssh.ClientConfig) { c.RekeyThreshold = n }
}
