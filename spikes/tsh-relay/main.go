// Command tsh-relay is a spike for running tsh through the hub. It stands
// in for the hub between tsh and a stock Teleport proxy: it terminates
// TLS, forwards HTTP requests, rewrites the proxy address in ping and
// find answers, and passes a /webapi/connectionupgrade WebSocket through
// as raw bytes. It logs every request, the ALPN protocols and SNI of each
// inner TLS ClientHello, and the WebSocket control frames on each
// upgrade, so that the spike can record what tsh sends.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:18443", "address to listen on")
	certFile := flag.String("cert", "", "TLS certificate chain for the relay's name")
	keyFile := flag.String("key", "", "TLS key for the relay's name")
	public := flag.String("public", "", "the relay's address as tsh sees it, host:port")
	upstream := flag.String("upstream", "127.0.0.1:3780", "the proxy's web listener to dial")
	upstreamAddr := flag.String("upstream-addr", "", "the proxy's public_addr, host:port, used as SNI and Host")
	flag.Parse()
	if *certFile == "" || *keyFile == "" || *public == "" || *upstreamAddr == "" {
		log.Fatal("-cert, -key, -public and -upstream-addr are required")
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	r, err := newRelay(*public, *upstream, *upstreamAddr, nil)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:      *listen,
		Handler:   r,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}},
	}
	log.Printf("relay: listening on %s as %s, upstream %s as %s", *listen, *public, *upstream, *upstreamAddr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// relay forwards requests to one Teleport proxy.
type relay struct {
	public       string
	upstream     string
	upstreamAddr string
	tlsConfig    *tls.Config
	proxy        *httputil.ReverseProxy
	nextID       atomic.Int64
}

// newRelay returns a relay that dials upstream and verifies its
// certificate for the host of upstreamAddr. If roots is nil, the system
// roots are used.
func newRelay(public, upstream, upstreamAddr string, roots *tlsRoots) (*relay, error) {
	host, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("upstream-addr: %w", err)
	}
	r := &relay{
		public:       public,
		upstream:     upstream,
		upstreamAddr: upstreamAddr,
		tlsConfig:    &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}, RootCAs: roots.pool()},
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upstream)
		},
		TLSClientConfig:   r.tlsConfig,
		ForceAttemptHTTP2: false,
	}
	r.proxy = &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = upstreamAddr
			pr.Out.Host = upstreamAddr
			pr.Out.Header.Del("Accept-Encoding")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Real-IP")
		},
		ModifyResponse: r.modifyResponse,
	}
	return r, nil
}

func (r *relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("http: %s %s from %s ua=%q", req.Method, req.URL.RequestURI(), req.RemoteAddr, req.UserAgent())
	if req.URL.Path == "/webapi/connectionupgrade" && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		r.serveUpgrade(w, req)
		return
	}
	r.proxy.ServeHTTP(w, req)
}

// isPing reports whether path is a ping or find answer that names the
// proxy's address.
func isPing(path string) bool {
	return path == "/webapi/ping" || path == "/webapi/find" || strings.HasPrefix(path, "/webapi/ping/")
}

func (r *relay) modifyResponse(resp *http.Response) error {
	log.Printf("http: %s %s -> %d", resp.Request.Method, resp.Request.URL.RequestURI(), resp.StatusCode)
	if resp.StatusCode != http.StatusOK || !isPing(resp.Request.URL.Path) {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	out, err := rewritePing(body, r.public)
	if err != nil {
		return fmt.Errorf("rewriting %s: %w", resp.Request.URL.Path, err)
	}
	log.Printf("ping: rewrote %s, proxy.ssh.public_addr is now %s", resp.Request.URL.Path, r.public)
	resp.Body = io.NopCloser(strings.NewReader(string(out)))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprint(len(out)))
	return nil
}

// rewritePing sets proxy.ssh.public_addr in a ping or find answer to
// public, and clears the other addresses that would send tsh around the
// relay. Fields it does not know are kept.
func rewritePing(body []byte, public string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	proxy, ok := doc["proxy"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no proxy object")
	}
	ssh, _ := proxy["ssh"].(map[string]any)
	if ssh == nil {
		ssh = map[string]any{}
		proxy["ssh"] = ssh
	}
	ssh["public_addr"] = public
	for _, k := range []string{"ssh_public_addr", "ssh_tunnel_public_addr", "listen_addr", "tunnel_listen_addr", "web_listen_addr"} {
		delete(ssh, k)
	}
	if kube, ok := proxy["kube"].(map[string]any); ok {
		delete(kube, "public_addr")
		delete(kube, "listen_addr")
	}
	if db, ok := proxy["db"].(map[string]any); ok {
		for k := range db {
			if strings.HasSuffix(k, "_public_addr") || strings.HasSuffix(k, "_listen_addr") {
				delete(db, k)
			}
		}
	}
	return json.Marshal(doc)
}

// serveUpgrade sends the upgrade request to the proxy, and if the proxy
// switches protocols, copies bytes both ways and taps the WebSocket frames
// for the log.
func (r *relay) serveUpgrade(w http.ResponseWriter, req *http.Request) {
	id := r.nextID.Add(1)
	start := time.Now()
	logf := func(format string, args ...any) {
		log.Printf("ws %d: "+format, append([]any{id}, args...)...)
	}
	logf("upgrade, subprotocols %q", req.Header.Values("Sec-WebSocket-Protocol"))

	up, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", r.upstream, r.tlsConfig)
	if err != nil {
		logf("dial upstream: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	out := req.Clone(req.Context())
	out.URL.Scheme = "https"
	out.URL.Host = r.upstreamAddr
	out.Host = r.upstreamAddr
	out.RequestURI = ""
	out.Header.Del("X-Forwarded-For")
	if err := out.Write(up); err != nil {
		logf("write upgrade: %v", err)
		up.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	upr := bufio.NewReader(up)
	resp, err := http.ReadResponse(upr, out)
	if err != nil {
		logf("read upgrade response: %v", err)
		up.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	logf("upstream answered %d, subprotocol %q", resp.StatusCode, resp.Header.Get("Sec-WebSocket-Protocol"))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
		up.Close()
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		logf("cannot hijack")
		up.Close()
		return
	}
	client, cbuf, err := hj.Hijack()
	if err != nil {
		logf("hijack: %v", err)
		up.Close()
		return
	}
	if err := resp.Write(client); err != nil {
		logf("write 101: %v", err)
		client.Close()
		up.Close()
		return
	}

	fromClient := newFrameTap("client", logf)
	fromProxy := newFrameTap("proxy", logf)
	done := make(chan string, 2)
	go func() {
		n, err := io.Copy(up, io.TeeReader(cbuf, fromClient))
		logf("client to proxy ended after %d bytes: %v", n, err)
		up.Close()
		done <- "client"
	}()
	go func() {
		n, err := io.Copy(client, io.TeeReader(upr, fromProxy))
		logf("proxy to client ended after %d bytes: %v", n, err)
		client.Close()
		done <- "proxy"
	}()
	first := <-done
	<-done
	logf("closed by %s after %v, client sent %d pings, proxy sent %d pings", first, time.Since(start).Round(time.Second), fromClient.pings, fromProxy.pings)
}
