package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// The tsh path: `tsh` away from home logs in and connects through the hub
// on the host of an app in WEB_UI_APPS, with no hub cookie. The hub passes
// a short allowlist of requests on "proxy" streams from auth's callout to
// the home proxy's web listener, and gates what runs inside the connection
// upgrade by its TLS ClientHello.

// tshRoute is a request the tsh path takes.
type tshRoute int

const (
	tshNone tshRoute = iota
	// tshPing is a ping, whose answer the hub rewrites.
	tshPing
	// tshLogin is a passwordless login request, passed on as it is.
	tshLogin
	// tshUpgrade is the connection upgrade, a WebSocket that carries TLS.
	tshUpgrade
)

const (
	// tshHelloMax is the most bytes of the inner ClientHello the hub
	// buffers before it decides.
	tshHelloMax = 16 << 10
	// tshUpgradesPerIP and tshUpgradesTotal cap the open upgrades. The
	// total stays below the fork's cap of 32 proxy streams, so that some
	// streams stay free for ping and login requests.
	tshUpgradesPerIP = 8
	tshUpgradesTotal = 24
	// tshBodyMax is the most bytes of a login request body. A WebAuthn
	// answer is a few KB.
	tshBodyMax = 64 << 10
	// tshPingMax is the most bytes of a ping answer the hub rewrites.
	tshPingMax = 1 << 20
)

// tshSubprotocols are the WebSocket subprotocols of the upgrade, in the
// order the hub prefers them.
var tshSubprotocols = []string{"alpn-ping", "alpn"}

// routeTsh returns the tsh route of a request, or tshNone. Matching is
// exact on the method and on the path as the URL parser left it, so a
// path with %2F, //, a trailing slash or another prefix does not match.
// An upgrade must also offer a subprotocol in tshSubprotocols.
func routeTsh(method, path string, upgrade bool, protocols string) tshRoute {
	switch {
	case method == "GET" && !upgrade && (path == "/webapi/ping" || path == "/webapi/ping/passwordless"):
		return tshPing
	case method == "POST" && !upgrade && (path == "/webapi/mfa/login/begin" || path == "/webapi/mfa/login/finish"):
		return tshLogin
	case method == "GET" && upgrade && path == "/webapi/connectionupgrade" && pickSubprotocol(protocols) != "":
		return tshUpgrade
	}
	return tshNone
}

// pickSubprotocol returns the first of tshSubprotocols that the
// Sec-WebSocket-Protocol header value offers, or "".
func pickSubprotocol(header string) string {
	offered := map[string]bool{}
	for _, p := range strings.Split(header, ",") {
		offered[strings.TrimSpace(p)] = true
	}
	for _, p := range tshSubprotocols {
		if offered[p] {
			return p
		}
	}
	return ""
}

// rewritePing sets proxy.ssh.public_addr in a ping answer to public, and
// removes the other addresses that would send tsh around the hub. Without
// the rewrite, tsh replaces the address it was given with the proxy's
// public_addr, which resolves only at home. Fields it does not know are
// kept.
func rewritePing(body []byte, public string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	proxy, ok := doc["proxy"].(map[string]any)
	if !ok {
		return nil, errors.New("no proxy object")
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

// tshHeaderDropped reports whether the hub drops a request header on the
// tsh path. It keeps no cookie and no credential the client sent, and
// none of the forwarding headers, so that the proxy sees only the
// X-Forwarded-For the hub sets.
func tshHeaderDropped(name string) bool {
	switch {
	case name == "host", name == "cookie", name == "authorization",
		name == "forwarded", name == "x-real-ip", name == "origin",
		strings.HasPrefix(name, "x-forwarded-"), strings.HasPrefix(name, "cf-"),
		strings.HasPrefix(name, "sec-websocket-"), hopByHop[name]:
		return true
	}
	return false
}

// errShortHello means that the bytes so far do not hold a whole
// ClientHello.
var errShortHello = errors.New("short client hello")

// clientHello holds the fields of a TLS ClientHello that the gate checks.
type clientHello struct {
	sni  string
	alpn []string
}

// parseClientHello parses the TLS ClientHello at the start of b, which may
// span several TLS records. It returns errShortHello if b ends before the
// ClientHello does.
func parseClientHello(b []byte) (clientHello, error) {
	var hs []byte
	for len(b) > 0 {
		if len(b) < 5 {
			return clientHello{}, errShortHello
		}
		if b[0] != 0x16 {
			return clientHello{}, fmt.Errorf("record type %d is not handshake", b[0])
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			return clientHello{}, errShortHello
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
		if len(hs) >= 4 && len(hs) >= 4+(int(hs[1])<<16|int(hs[2])<<8|int(hs[3])) {
			break
		}
	}
	if len(hs) < 4 {
		return clientHello{}, errShortHello
	}
	if hs[0] != 1 {
		return clientHello{}, fmt.Errorf("handshake type %d is not client hello", hs[0])
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return clientHello{}, errShortHello
	}
	r := reader(hs[4 : 4+n])
	r.skip(2 + 32) // version, random
	r.skip(int(r.u8()))
	r.skip(int(r.u16()))
	r.skip(int(r.u8()))
	if r.err != nil {
		return clientHello{}, r.err
	}
	var h clientHello
	if len(r.b) == 0 {
		return h, nil
	}
	exts := reader(r.bytes(int(r.u16())))
	for len(exts.b) > 0 && exts.err == nil {
		typ := exts.u16()
		data := reader(exts.bytes(int(exts.u16())))
		switch typ {
		case 0: // server_name
			list := reader(data.bytes(int(data.u16())))
			for len(list.b) > 0 && list.err == nil {
				kind := list.u8()
				name := list.bytes(int(list.u16()))
				if kind == 0 {
					h.sni = string(name)
				}
			}
			if list.err != nil {
				return clientHello{}, list.err
			}
		case 16: // application_layer_protocol_negotiation
			list := reader(data.bytes(int(data.u16())))
			for len(list.b) > 0 && list.err == nil {
				h.alpn = append(h.alpn, string(list.bytes(int(list.u8()))))
			}
			if list.err != nil {
				return clientHello{}, list.err
			}
		}
		if data.err != nil {
			return clientHello{}, data.err
		}
	}
	if exts.err != nil {
		return clientHello{}, exts.err
	}
	return h, nil
}

// byteReader reads big-endian fields and remembers the first error.
type byteReader struct {
	b   []byte
	err error
}

func reader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n > len(r.b) {
		r.err = errors.New("malformed client hello")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *byteReader) skip(n int) { r.bytes(n) }

func (r *byteReader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *byteReader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// gateHello returns an error unless the ClientHello inside an upgrade is
// one that tsh sends to the home cluster. The SNI must be the encoded
// cluster name. The proxy's router serves the first protocol in the list
// that it has a handler for, so the first protocol must be on the
// allowlist. grpc-go adds h2 after a Teleport protocol, so h2 may follow,
// and nothing else may.
//
// The allowlist has auth's protocol, because tsh needs it to log in and to
// list nodes. It is a raw forward to auth, so auth's TLS endpoint is
// reachable through the hub for any client, and auth then asks for a user
// certificate.
func gateHello(h clientHello, cluster string) error {
	encoded := hex.EncodeToString([]byte(cluster))
	if h.sni != encoded+"."+apiDomain {
		return fmt.Errorf("server name %q is not the cluster's", h.sni)
	}
	if len(h.alpn) == 0 {
		return errors.New("no ALPN protocol")
	}
	allowed := map[string]bool{
		"teleport-proxy-ssh":       true,
		"teleport-proxy-ssh-grpc":  true,
		"teleport-proxy-grpc-mtls": true,
		"teleport-auth@" + encoded: true,
	}
	if !allowed[h.alpn[0]] {
		return fmt.Errorf("ALPN protocol %q is not allowed", h.alpn[0])
	}
	for _, p := range h.alpn[1:] {
		if !allowed[p] && p != "h2" {
			return fmt.Errorf("ALPN protocol %q is not allowed", p)
		}
	}
	return nil
}

// upgradeCaps counts the open upgrades, per client address and in total.
type upgradeCaps struct {
	mu    sync.Mutex
	perIP map[string]int
	total int
}

// acquire takes a slot for ip, and reports false when ip or the hub is at
// its cap.
func (c *upgradeCaps) acquire(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.perIP == nil {
		c.perIP = make(map[string]int)
	}
	if c.total >= tshUpgradesTotal || c.perIP[ip] >= tshUpgradesPerIP {
		return false
	}
	c.perIP[ip]++
	c.total++
	return true
}

// release gives back a slot that acquire took for ip.
func (c *upgradeCaps) release(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.perIP[ip] <= 1 {
		delete(c.perIP, ip)
	} else {
		c.perIP[ip]--
	}
	c.total--
}
