package conformance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

// The x-teleport-* extensions on an agent's SSH host certificate.
const (
	ExtRole      = "x-teleport-role"
	ExtAuthority = "x-teleport-authority"
)

// PKI is a test cluster's host CA, the hub identity it signs, and the
// callout key, all generated for one test run.
type PKI struct {
	Cluster string
	// HubHost is the name in the hub TLS certificate.
	HubHost string
	// HubUUID is the hub's host UUID. Its SSH host certificate has the
	// principal HubUUID.Cluster.
	HubUUID string

	HostCA    ssh.Signer
	hostCAKey ed25519.PrivateKey
	TLSCA     *x509.Certificate
	TLSCAPool *x509.CertPool
	tlsCAKey  *ecdsa.PrivateKey

	hubTLSCertPEM, hubTLSKeyPEM []byte
	hubSSHKeyPEM, hubSSHCert    []byte

	Callout ed25519.PrivateKey
}

// NewPKI generates a host CA for cluster and the hub identity for hubHost.
func NewPKI(cluster, hubHost string) (*PKI, error) {
	p := &PKI{Cluster: cluster, HubHost: hubHost, HubUUID: NewUUID()}

	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p.hostCAKey = caKey
	if p.HostCA, err = ssh.NewSignerFromKey(caKey); err != nil {
		return nil, err
	}

	if p.tlsCAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cluster, Organization: []string{cluster}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &p.tlsCAKey.PublicKey, p.tlsCAKey)
	if err != nil {
		return nil, err
	}
	if p.TLSCA, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	p.TLSCAPool = x509.NewCertPool()
	p.TLSCAPool.AddCert(p.TLSCA)

	if p.hubTLSCertPEM, p.hubTLSKeyPEM, err = p.tlsLeaf(p.subject(hubHost), []string{hubHost}); err != nil {
		return nil, err
	}

	_, hubKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(hubKey, "")
	if err != nil {
		return nil, err
	}
	p.hubSSHKeyPEM = pem.EncodeToMemory(block)
	hubSigner, err := ssh.NewSignerFromKey(hubKey)
	if err != nil {
		return nil, err
	}
	hubCert, err := p.SignHost(hubSigner.PublicKey(), CertSpec{
		Principals: []string{p.HubUUID + "." + cluster, p.HubUUID},
		Role:       "Proxy",
	})
	if err != nil {
		return nil, err
	}
	p.hubSSHCert = ssh.MarshalAuthorizedKey(hubCert)

	if _, p.Callout, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return nil, err
	}
	return p, nil
}

// Secrets returns the hub's secrets, base64 as both hubs read them.
func (p *PKI) Secrets() map[string]string {
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	return map[string]string{
		"HUB_TLS_CERT":        b64(p.hubTLSCertPEM),
		"HUB_TLS_KEY":         b64(p.hubTLSKeyPEM),
		"HUB_SSH_KEY":         b64(p.hubSSHKeyPEM),
		"HUB_SSH_CERT":        b64(p.hubSSHCert),
		"HOST_CA_SSH":         b64(ssh.MarshalAuthorizedKey(p.HostCA.PublicKey())),
		"HOST_CA_TLS":         b64(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.TLSCA.Raw})),
		"AUTH_CALLOUT_PUBKEY": b64(p.Callout.Public().(ed25519.PublicKey)),
	}
}

// CertSpec describes an SSH host certificate. A zero ValidAfter and
// ValidBefore mean from an hour ago to an hour from now.
type CertSpec struct {
	Principals  []string
	Role        string
	Authority   string
	CertType    uint32
	ValidAfter  time.Time
	ValidBefore time.Time
}

// SignHost signs pub with the host CA.
func (p *PKI) SignHost(pub ssh.PublicKey, spec CertSpec) (*ssh.Certificate, error) {
	return signWith(p.HostCA, pub, spec, p.Cluster)
}

func signWith(ca ssh.Signer, pub ssh.PublicKey, spec CertSpec, cluster string) (*ssh.Certificate, error) {
	after, before := spec.ValidAfter, spec.ValidBefore
	if after.IsZero() {
		after = time.Now().Add(-time.Hour)
	}
	if before.IsZero() {
		before = time.Now().Add(time.Hour)
	}
	authority := spec.Authority
	if authority == "" {
		authority = cluster
	}
	certType := spec.CertType
	if certType == 0 {
		certType = ssh.HostCert
	}
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        certType,
		KeyId:           spec.Principals[0],
		ValidPrincipals: spec.Principals,
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			ExtRole:      spec.Role,
			ExtAuthority: authority,
		}},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return cert, nil
}

// subject returns the certificate subject for cn in the test cluster.
func (p *PKI) subject(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{p.Cluster}}
}

// tlsLeaf returns a PEM certificate and PKCS #8 key signed by the TLS CA.
func (p *PKI) tlsLeaf(subject pkix.Name, dnsNames []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.TLSCA, &key.PublicKey, p.tlsCAKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// TLSLeaf returns a TLS certificate signed by the TLS CA.
func (p *PKI) TLSLeaf(cn string, dnsNames ...string) (tls.Certificate, error) {
	certPEM, keyPEM, err := p.tlsLeaf(p.subject(cn), dnsNames)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// OtherCA returns an SSH CA that the hub does not trust.
func OtherCA() (ssh.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// SignWith signs pub with ca, which need not be the cluster's host CA.
func (p *PKI) SignWith(ca ssh.Signer, pub ssh.PublicKey, spec CertSpec) (*ssh.Certificate, error) {
	return signWith(ca, pub, spec, p.Cluster)
}

// NewUUID returns a random version 4 UUID, the form of a Teleport host ID.
func NewUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
