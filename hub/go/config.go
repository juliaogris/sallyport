package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The vars and secrets the hub reads from its env. Secrets are base64 so
// that multi-line PEM survives `wrangler secret put`.
var envNames = []string{
	"CLUSTER_NAME", "PUBLIC_ADDR", "SERVER_VERSION", "CALLOUT_HOST",
	"DOMAIN", "OWNER", "APPS",
	"HUB_TLS_CERT", "HUB_TLS_KEY", "HUB_SSH_KEY", "HUB_SSH_CERT",
	"HOST_CA_SSH", "HOST_CA_TLS", "AUTH_CALLOUT_PUBKEY", "HUB_MODE",
}

// config is the hub's parsed env. A secret that does not parse leaves its
// field empty and its error in errs, so that only the features that need
// it fail.
type config struct {
	cluster     string
	calloutHost string
	owner       string
	domain      string
	apps        []app
	// lazy is true when HUB_MODE is lazy: auth's callout keeps one control
	// socket open, and the hub asks it for a stream each time it needs one.
	lazy bool

	// tlsCert is the hub TLS identity: the tunnel's server certificate and
	// the client certificate toward auth.
	tlsCert *tls.Certificate
	// sshSigner is the hub host key with its host certificate.
	sshSigner ssh.Signer
	// proxyName is the hub's host UUID, from the host certificate's first
	// principal.
	proxyName string
	hostCA    ssh.PublicKey
	hostCATLS *x509.CertPool
	calloutPK ed25519.PublicKey

	errs map[string]error
}

// app is one dashboard app and the path a launch lands on.
type app struct {
	name, start string
}

func parseConfig(env map[string]string) *config {
	c := &config{
		cluster:     env["CLUSTER_NAME"],
		calloutHost: env["CALLOUT_HOST"],
		owner:       env["OWNER"],
		domain:      env["DOMAIN"],
		apps:        parseApps(env["APPS"]),
		lazy:        env["HUB_MODE"] == "lazy",
		errs:        make(map[string]error),
	}
	secret := func(name string) []byte {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env[name]))
		if err == nil && len(b) == 0 {
			err = errors.New("not set")
		}
		if err != nil {
			c.errs[name] = fmt.Errorf("%s: %w", name, err)
			return nil
		}
		return b
	}

	if cert, key := secret("HUB_TLS_CERT"), secret("HUB_TLS_KEY"); cert != nil && key != nil {
		kp, err := tls.X509KeyPair(cert, key)
		if err != nil {
			c.errs["HUB_TLS_CERT"] = fmt.Errorf("hub tls identity: %w", err)
		} else {
			c.tlsCert = &kp
		}
	}
	if key, cert := secret("HUB_SSH_KEY"), secret("HUB_SSH_CERT"); key != nil && cert != nil {
		signer, name, err := hostSigner(key, cert, c.cluster)
		if err != nil {
			c.errs["HUB_SSH_CERT"] = err
		} else {
			c.sshSigner, c.proxyName = signer, name
		}
	}
	if b := secret("HOST_CA_SSH"); b != nil {
		pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			c.errs["HOST_CA_SSH"] = fmt.Errorf("HOST_CA_SSH: %w", err)
		} else {
			c.hostCA = pk
		}
	}
	if b := secret("HOST_CA_TLS"); b != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			c.errs["HOST_CA_TLS"] = errors.New("HOST_CA_TLS: no certificates")
		} else {
			c.hostCATLS = pool
		}
	}
	if b := secret("AUTH_CALLOUT_PUBKEY"); b != nil {
		if len(b) != ed25519.PublicKeySize {
			c.errs["AUTH_CALLOUT_PUBKEY"] = errors.New("AUTH_CALLOUT_PUBKEY is not 32 bytes")
		} else {
			c.calloutPK = ed25519.PublicKey(b)
		}
	}
	return c
}

// err returns the first parse error among the named secrets, or nil.
func (c *config) err(names ...string) error {
	for _, n := range names {
		if err := c.errs[n]; err != nil {
			return err
		}
	}
	return nil
}

// hostSigner returns the host key signer that presents the host
// certificate, which is the only form the agent accepts, and the proxy
// name: the first principal without the cluster suffix.
func hostSigner(keyPEM, certLine []byte, cluster string) (ssh.Signer, string, error) {
	key, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("HUB_SSH_KEY: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		return nil, "", fmt.Errorf("HUB_SSH_CERT: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, "", errors.New("HUB_SSH_CERT: not a certificate")
	}
	if len(cert.ValidPrincipals) == 0 {
		return nil, "", errors.New("HUB_SSH_CERT: no principals")
	}
	signer, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		return nil, "", fmt.Errorf("HUB_SSH_CERT: %w", err)
	}
	return signer, strings.TrimSuffix(cert.ValidPrincipals[0], "."+cluster), nil
}

// parseApps parses APPS, a comma-separated list of `name` or
// `name:/start/path`.
func parseApps(s string) []app {
	var out []app
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		name, path, ok := strings.Cut(e, ":")
		if !ok {
			path = "/"
		}
		if validName(name) && validStart(path) {
			out = append(out, app{name, path})
		}
	}
	return out
}

// validStart reports whether p starts with one `/`, has only bytes 0x21
// to 0x7e other than `\`, and has no `.` or `..` segment. The URL parser
// removes tab, CR and LF, reads `\` as `/` and removes dot segments, so any
// of them could turn the path into `//host`. handoffPage applies the same
// rule to the start path it is sent.
func validStart(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return false
	}
	for i := range len(p) {
		if p[i] <= ' ' || p[i] > '~' || p[i] == '\\' {
			return false
		}
	}
	return !hasDotSegment(p)
}

// hasDotSegment reports whether the path part of p has a `.` or `..`
// segment, also written `%2e`.
func hasDotSegment(p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for _, seg := range strings.Split(p, "/") {
		seg = strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// validName reports whether name matches ^[a-z][a-z0-9]*$ and is at most
// 30 bytes.
func validName(name string) bool {
	if name == "" || len(name) > 30 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// hostKind is the kind of host a request is for.
type hostKind int

const (
	hostNone hostKind = iota
	hostLogin
	hostApp
)

// classify returns the host kind and, for an app host, the app name. App
// names match ^[a-z][a-z0-9]*$, so `<app>-<owner>` splits once.
func (c *config) classify(host string) (hostKind, string) {
	if c.owner == "" || c.domain == "" {
		return hostNone, ""
	}
	label, ok := strings.CutSuffix(host, "."+c.domain)
	if !ok {
		return hostNone, ""
	}
	if label == c.owner {
		return hostLogin, ""
	}
	name, ok := strings.CutSuffix(label, "-"+c.owner)
	if !ok || !validName(name) {
		return hostNone, ""
	}
	return hostApp, name
}

func (c *config) loginHost() string { return c.owner + "." + c.domain }
