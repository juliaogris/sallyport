package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCertForHost(t *testing.T) {
	const host = "bench-julia.example.com"
	appName := asn1.ObjectIdentifier{1, 3, 9999, 1, 10}
	tests := []struct {
		name  string
		extra []pkix.AttributeTypeAndValue
		want  bool
	}{
		{
			name: "address after another attribute",
			extra: []pkix.AttributeTypeAndValue{
				{Type: appName, Value: "bench"},
				{Type: appPublicAddrOID, Value: host},
			},
			want: true,
		},
		{
			name:  "address of another app host",
			extra: []pkix.AttributeTypeAndValue{{Type: appPublicAddrOID, Value: "other-julia.example.com"}},
			want:  false,
		},
		{
			name:  "no address",
			extra: []pkix.AttributeTypeAndValue{{Type: appName, Value: "bench"}},
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certForHost(testCert(t, tt.extra), host); got != tt.want {
				t.Errorf("certForHost = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("not a certificate", func(t *testing.T) {
		if certForHost([]byte("not pem"), host) {
			t.Error("certForHost = true for bytes that are not PEM")
		}
	})
}

// testCert returns a PEM self-signed certificate with extra in its subject.
func testCert(t *testing.T, extra []pkix.AttributeTypeAndValue) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "julia", ExtraNames: extra},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
