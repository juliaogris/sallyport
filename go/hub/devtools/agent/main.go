// Command agent stands in for a Teleport app service when testing a hub
// that the real agent cannot use, such as the dev Worker, whose host name
// is not in the hub's SSH host certificate. It dials the hub's reverse
// tunnel with an identity exported from an agent's data directory:
//
//   - With -role app it opens teleport-heartbeat, pings, answers the hub's
//     discovery requests and test dial, and sends keepalives.
//   - With -role instance it opens teleport-transport to
//     @remote-auth-server, runs TLS to auth through it and calls Ping.
//
// The identity file is the JSON of /ids/app/current or
// /ids/instance/current in the agent's proc database.
//
//	agent -url wss://HOST -id app.json -role app -for 60s
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type identity struct {
	Spec struct {
		Key        string   `json:"key"`
		SSHCert    string   `json:"ssh_cert"`
		TLSCert    string   `json:"tls_cert"`
		TLSCACerts []string `json:"tls_ca_certs"`
	} `json:"spec"`
}

func main() {
	rawURL := flag.String("url", "", "the hub's wss:// base URL")
	idPath := flag.String("id", "", "the identity JSON")
	role := flag.String("role", "app", "app or instance")
	sni := flag.String("sni", "go.example.com", "the name the hub TLS certificate is checked against")
	plain := flag.Bool("plain", false, "authenticate with a plain key instead of the certificate, which the hub must reject")
	cluster := flag.String("cluster", "sallyport-go", "the cluster name")
	dur := flag.Duration("for", time.Minute, "how long the app role stays connected")
	flag.Parse()

	b, err := os.ReadFile(*idPath)
	if err != nil {
		log.Fatal(err)
	}
	var id identity
	if err := json.Unmarshal(b, &id); err != nil {
		log.Fatal(err)
	}
	dec := func(s string) []byte {
		out, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			log.Fatal(err)
		}
		return out
	}
	keyPEM, certPEM := dec(id.Spec.Key), dec(id.Spec.TLSCert)
	roots := x509.NewCertPool()
	for _, c := range id.Spec.TLSCACerts {
		roots.AppendCertsFromPEM(dec(c))
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(dec(id.Spec.SSHCert))
	if err != nil {
		log.Fatal(err)
	}
	cert := pub.(*ssh.Certificate)
	auth := signer
	if !*plain {
		if auth, err = ssh.NewCertSigner(cert, signer); err != nil {
			log.Fatal(err)
		}
	}

	hdr := http.Header{"Sec-WebSocket-Protocol": {"alpn-ping"}}
	ws, resp, err := websocket.DefaultDialer.Dial(*rawURL+"/webapi/connectionupgrade", hdr)
	if err != nil {
		log.Fatalf("websocket: %v (%v)", err, resp)
	}
	log.Printf("websocket up, subprotocol %q", ws.Subprotocol())
	tc := tls.Client(&wsConn{ws: ws}, &tls.Config{ServerName: *sni, RootCAs: roots, NextProtos: []string{"teleport-reversetunnel"}})
	if err := tc.Handshake(); err != nil {
		log.Fatalf("tls: %v", err)
	}
	log.Printf("tls up, alpn %q", tc.ConnectionState().NegotiatedProtocol)
	// The agent's SSH user is <host UUID>.<cluster>.
	user := cert.ValidPrincipals[0]
	for _, p := range cert.ValidPrincipals {
		if prefix, ok := strings.CutSuffix(p, "."+*cluster); ok && len(prefix) == 36 {
			user = p
		}
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(auth)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(tc, "hub", cfg)
	if err != nil {
		log.Fatalf("ssh as %q: %v", user, err)
	}
	log.Printf("ssh up as %q, server %s", user, sc.ServerVersion())
	go ssh.DiscardRequests(reqs)
	go serveChannels(chans)

	switch *role {
	case "app":
		runApp(sc, *dur)
	case "instance":
		runInstance(sc, tlsCert, roots)
	}
	sc.Close()
}

// serveChannels answers the channels the hub opens: discovery requests
// are logged and a transport dial is accepted and closed.
func serveChannels(chans <-chan ssh.NewChannel) {
	for nc := range chans {
		typ := nc.ChannelType()
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			go io.Copy(io.Discard, ch)
			for r := range creqs {
				log.Printf("hub channel %s: request %s %s", typ, r.Type, r.Payload)
				if r.WantReply {
					r.Reply(true, nil)
				}
				if typ == "teleport-transport" {
					return
				}
			}
		}()
	}
}

func runApp(sc ssh.Conn, dur time.Duration) {
	ch, reqs, err := sc.OpenChannel("teleport-heartbeat", nil)
	if err != nil {
		log.Fatalf("heartbeat: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	end := time.Now().Add(dur)
	for time.Now().Before(end) {
		ok, err := ch.SendRequest("ping", true, []byte("devagent"))
		log.Printf("ping: %v %v", ok, err)
		ok, _, err = sc.SendRequest("keepalive@openssh.com", true, nil)
		log.Printf("keepalive: %v %v", ok, err)
		if err != nil {
			return
		}
		time.Sleep(20 * time.Second)
	}
	// A transport to anything but auth must be refused.
	if t, treqs, err := sc.OpenChannel("teleport-transport", nil); err == nil {
		go ssh.DiscardRequests(treqs)
		ok, err := t.SendRequest("teleport-transport-dial", true, []byte(`{"address":"127.0.0.1:22"}`))
		log.Printf("dial to 127.0.0.1:22: %v %v", ok, err)
	}
	if _, _, err := sc.OpenChannel("session", nil); err != nil {
		log.Printf("session channel: %v", err)
	}
}

func runInstance(sc ssh.Conn, cert tls.Certificate, roots *x509.CertPool) {
	ch, reqs, err := sc.OpenChannel("teleport-transport", nil)
	if err != nil {
		log.Fatalf("transport: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	ok, err := ch.SendRequest("teleport-transport-dial", true, []byte(`{"address":"@remote-auth-server"}`))
	log.Printf("dial @remote-auth-server: %v %v", ok, err)
	if !ok {
		return
	}
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	tr := &http.Transport{
		Protocols: protos,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			tc := tls.Client(chanConn{ch}, &tls.Config{ServerName: "teleport.cluster.local", RootCAs: roots, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
			return tc, tc.HandshakeContext(ctx)
		},
	}
	cc, err := tr.NewClientConn(context.Background(), "https", "teleport.cluster.local:443")
	if err != nil {
		log.Fatalf("auth conn: %v", err)
	}
	for range 3 {
		req, _ := http.NewRequest("POST", "https://teleport.cluster.local/proto.AuthService/Ping", bytes.NewReader(make([]byte, 5)))
		req.Header.Set("content-type", "application/grpc")
		req.Header.Set("te", "trailers")
		start := time.Now()
		resp, err := cc.RoundTrip(req)
		if err != nil {
			log.Fatalf("ping: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		n := 0
		if len(body) >= 5 {
			n = int(binary.BigEndian.Uint32(body[1:5]))
		}
		log.Printf("auth Ping through the passthrough: grpc-status %q, %d byte message, %v", resp.Trailer.Get("grpc-status"), n, time.Since(start))
		if n > 0 && bytes.Contains(body, []byte("sallyport")) {
			i := bytes.Index(body, []byte("sallyport"))
			log.Printf("  cluster in reply: %q", body[i:min(len(body), i+12)])
		}
	}
	cc.Close()
}

// wsConn is a net.Conn over a gorilla WebSocket with binary messages.
type wsConn struct {
	ws  *websocket.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *wsConn) Read(b []byte) (int, error) {
	for len(c.buf) == 0 {
		_, m, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		c.buf = m
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *wsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error                     { return c.ws.Close() }
func (c *wsConn) LocalAddr() net.Addr              { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr             { return c.ws.RemoteAddr() }
func (c *wsConn) SetDeadline(time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(time.Time) error { return nil }

type chanConn struct{ ssh.Channel }

func (chanConn) LocalAddr() net.Addr              { return nil }
func (chanConn) RemoteAddr() net.Addr             { return nil }
func (chanConn) SetDeadline(time.Time) error      { return nil }
func (chanConn) SetReadDeadline(time.Time) error  { return nil }
func (chanConn) SetWriteDeadline(time.Time) error { return nil }
