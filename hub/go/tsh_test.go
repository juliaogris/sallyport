package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestRouteTsh(t *testing.T) {
	cases := []struct {
		method, path string
		upgrade      bool
		protocols    string
		want         tshRoute
	}{
		{"GET", "/webapi/ping", false, "", tshPing},
		{"GET", "/webapi/ping/passwordless", false, "", tshPing},
		{"POST", "/webapi/mfa/login/begin", false, "", tshLogin},
		{"POST", "/webapi/mfa/login/finish", false, "", tshLogin},
		{"GET", "/webapi/connectionupgrade", true, "alpn-ping", tshUpgrade},
		{"GET", "/webapi/connectionupgrade", true, "alpn", tshUpgrade},
		{"GET", "/webapi/connectionupgrade", true, "chat, alpn-ping", tshUpgrade},

		// Near misses.
		{"GET", "/webapi/pingx", false, "", tshNone},
		{"GET", "/webapi/ping/", false, "", tshNone},
		{"GET", "/webapi/ping/local", false, "", tshNone},
		{"GET", "/webapi/ping%2Fpasswordless", false, "", tshNone},
		{"GET", "//webapi/ping", false, "", tshNone},
		{"GET", "/v1/webapi/ping", false, "", tshNone},
		{"HEAD", "/webapi/ping", false, "", tshNone},
		{"POST", "/webapi/ping", false, "", tshNone},
		{"GET", "/webapi/mfa/login/begin", false, "", tshNone},
		{"POST", "/webapi/mfa/login/begin/", false, "", tshNone},
		{"GET", "/webapi/ping", true, "alpn-ping", tshNone},
		{"POST", "/webapi/mfa/login/begin", true, "alpn-ping", tshNone},
		{"GET", "/webapi/connectionupgrade", false, "alpn-ping", tshNone},
		{"GET", "/webapi/connectionupgrade", true, "", tshNone},
		{"GET", "/webapi/connectionupgrade", true, "alpnx", tshNone},
		{"POST", "/webapi/connectionupgrade", true, "alpn-ping", tshNone},
		{"GET", "/webapi/find", false, "", tshNone},
		{"GET", "/webapi/sites", false, "", tshNone},
		{"POST", "/webapi/sessions/web", false, "", tshNone},
	}
	for _, c := range cases {
		if got := routeTsh(c.method, c.path, c.upgrade, c.protocols); got != c.want {
			t.Errorf("routeTsh(%s %s, upgrade %v, %q) = %d, want %d", c.method, c.path, c.upgrade, c.protocols, got, c.want)
		}
	}
}

func TestPickSubprotocol(t *testing.T) {
	for header, want := range map[string]string{
		"alpn-ping":        "alpn-ping",
		"alpn":             "alpn",
		"alpn, alpn-ping":  "alpn-ping",
		" alpn ":           "alpn",
		"":                 "",
		"chat":             "",
		"alpn-pingx, alpn": "alpn",
	} {
		if got := pickSubprotocol(header); got != want {
			t.Errorf("pickSubprotocol(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestRewritePing(t *testing.T) {
	in := `{"auth":{"type":"local"},"proxy":{"kube":{"enabled":true,"public_addr":"k.lan:3026","listen_addr":"0.0.0.0:3026"},
	"ssh":{"listen_addr":"0.0.0.0:3023","tunnel_listen_addr":"0.0.0.0:3024","web_listen_addr":"0.0.0.0:3080",
	"public_addr":"teleport.julia.sally.red:3080","ssh_public_addr":"x:3023","ssh_tunnel_public_addr":"x:3024"},
	"db":{"postgres_public_addr":"p:5432","mysql_listen_addr":"m:3036","enabled":true},
	"tls_routing_enabled":true},"server_version":"18.11.1","cluster_name":"sallyport"}`
	out, err := rewritePing([]byte(in), "tp.julia.sally.red:443")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	proxy := doc["proxy"].(map[string]any)
	ssh := proxy["ssh"].(map[string]any)
	if len(ssh) != 1 || ssh["public_addr"] != "tp.julia.sally.red:443" {
		t.Errorf("ssh = %v, want only public_addr tp.julia.sally.red:443", ssh)
	}
	if kube := proxy["kube"].(map[string]any); len(kube) != 1 || kube["enabled"] != true {
		t.Errorf("kube = %v, want only enabled", kube)
	}
	if db := proxy["db"].(map[string]any); len(db) != 1 || db["enabled"] != true {
		t.Errorf("db = %v, want only enabled", db)
	}
	if proxy["tls_routing_enabled"] != true || doc["cluster_name"] != "sallyport" || doc["auth"] == nil {
		t.Errorf("fields the rewrite does not know were lost: %s", out)
	}
	if strings.Contains(string(out), "teleport.julia.sally.red") {
		t.Errorf("the proxy's own address is still in %s", out)
	}

	for _, bad := range []string{`not json`, `{}`, `{"proxy":"x"}`} {
		if _, err := rewritePing([]byte(bad), "h:443"); err == nil {
			t.Errorf("rewritePing(%q) did not fail", bad)
		}
	}
	// A ping with no ssh object gets one.
	out, err = rewritePing([]byte(`{"proxy":{}}`), "h:443")
	if err != nil || !strings.Contains(string(out), `"public_addr":"h:443"`) {
		t.Errorf("rewritePing without ssh = %s, %v", out, err)
	}
}

func TestTshHeaderDropped(t *testing.T) {
	for _, name := range []string{
		"host", "cookie", "authorization", "forwarded", "x-real-ip", "origin",
		"x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
		"cf-connecting-ip", "cf-ray", "connection", "upgrade", "te",
		"sec-websocket-key", "sec-websocket-protocol", "sec-websocket-version",
		"sec-websocket-extensions",
	} {
		if !tshHeaderDropped(name) {
			t.Errorf("header %q is kept", name)
		}
	}
	for _, name := range []string{"content-type", "accept", "user-agent", "accept-language"} {
		if tshHeaderDropped(name) {
			t.Errorf("header %q is dropped", name)
		}
	}
}

// clientHelloBytes returns the bytes of the ClientHello that a Go TLS
// client sends with cfg.
func clientHelloBytes(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		tls.Client(c, cfg).Handshake()
		c.Close()
	}()
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := s.Read(buf)
		out = append(out, buf[:n]...)
		if _, perr := parseClientHello(out); perr == nil || err != nil {
			break
		}
	}
	return out
}

func TestParseClientHello(t *testing.T) {
	sni := hex.EncodeToString([]byte("sallyport")) + "." + apiDomain
	b := clientHelloBytes(t, &tls.Config{ServerName: sni, NextProtos: []string{"teleport-proxy-ssh-grpc", "h2"}})
	h, err := parseClientHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.sni != sni || strings.Join(h.alpn, ",") != "teleport-proxy-ssh-grpc,h2" {
		t.Fatalf("got sni %q alpn %v", h.sni, h.alpn)
	}
	for i := 0; i < len(b); i++ {
		if _, err := parseClientHello(b[:i]); err != errShortHello {
			t.Fatalf("parseClientHello of %d of %d bytes = %v, want errShortHello", i, len(b), err)
		}
	}

	// The same ClientHello split into two TLS records.
	hs := b[5:]
	split := append([]byte{0x16, b[1], b[2], 0, 40}, hs[:40]...)
	rest := hs[40:]
	split = append(split, 0x16, b[1], b[2], byte(len(rest)>>8), byte(len(rest)))
	split = append(split, rest...)
	h2, err := parseClientHello(split)
	if err != nil || h2.sni != sni {
		t.Fatalf("split records: %v, %v", h2, err)
	}

	if _, err := parseClientHello([]byte("GET / HTTP/1.1\r\n\r\n")); err == nil || err == errShortHello {
		t.Errorf("plain HTTP parsed as a client hello: %v", err)
	}
	bad := append([]byte(nil), b...)
	bad[5] = 2 // server hello
	if _, err := parseClientHello(bad); err == nil || err == errShortHello {
		t.Errorf("a server hello parsed: %v", err)
	}
}

func TestGateHello(t *testing.T) {
	enc := hex.EncodeToString([]byte("sallyport"))
	sni := enc + "." + apiDomain
	cases := []struct {
		name string
		h    clientHello
		ok   bool
	}{
		{"ssh grpc", clientHello{sni, []string{"teleport-proxy-ssh-grpc", "h2"}}, true},
		{"auth", clientHello{sni, []string{"teleport-auth@" + enc, "h2"}}, true},
		{"ssh", clientHello{sni, []string{"teleport-proxy-ssh"}}, true},
		{"grpc mtls", clientHello{sni, []string{"teleport-proxy-grpc-mtls", "h2"}}, true},

		{"no alpn", clientHello{sni, nil}, false},
		{"h2 first", clientHello{sni, []string{"h2", "teleport-proxy-ssh-grpc"}}, false},
		{"http/1.1", clientHello{sni, []string{"http/1.1"}}, false},
		{"h2 only", clientHello{sni, []string{"h2"}}, false},
		{"join service", clientHello{sni, []string{"teleport-proxy-grpc", "h2"}}, false},
		{"mixed", clientHello{sni, []string{"teleport-proxy-ssh-grpc", "http/1.1"}}, false},
		{"other cluster auth", clientHello{sni, []string{"teleport-auth@" + hex.EncodeToString([]byte("other"))}}, false},
		{"reverse tunnel", clientHello{sni, []string{"teleport-reversetunnel"}}, false},
		{"wrong sni", clientHello{"tp.julia.sally.red", []string{"teleport-proxy-ssh-grpc"}}, false},
		{"other cluster sni", clientHello{hex.EncodeToString([]byte("other")) + "." + apiDomain, []string{"teleport-proxy-ssh-grpc"}}, false},
		{"no sni", clientHello{"", []string{"teleport-proxy-ssh-grpc"}}, false},
	}
	for _, c := range cases {
		err := gateHello(c.h, "sallyport")
		if (err == nil) != c.ok {
			t.Errorf("%s: gateHello = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

func TestUpgradeCaps(t *testing.T) {
	var c upgradeCaps
	for range tshUpgradesPerIP {
		if !c.acquire("a") {
			t.Fatal("acquire below the per-IP cap failed")
		}
	}
	if c.acquire("a") {
		t.Fatal("acquire above the per-IP cap succeeded")
	}
	c.release("a")
	if !c.acquire("a") {
		t.Fatal("acquire after a release failed")
	}
	n := tshUpgradesPerIP
	for i := 0; n < tshUpgradesTotal; i++ {
		ip := string(rune('b' + i/tshUpgradesPerIP))
		if !c.acquire(ip) {
			t.Fatalf("acquire %d below the total cap failed", n)
		}
		n++
	}
	if c.acquire("z") {
		t.Fatal("acquire above the total cap succeeded")
	}
	c.release("b")
	if !c.acquire("z") {
		t.Fatal("acquire after a release at the total cap failed")
	}
}
