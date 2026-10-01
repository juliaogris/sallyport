package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

// appPublicAddrOID is the subject attribute of a Teleport user certificate
// with the app session's public address, Teleport's
// tlsca.AppPublicAddrASN1ExtensionOID.
var appPublicAddrOID = asn1.ObjectIdentifier{1, 3, 9999, 1, 6}

// certForHost returns true when the first certificate in certPEM parses
// and its app public address is host. A certificate with no address
// returns false.
func certForHost(certPEM []byte, host string) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	for _, n := range cert.Subject.Names {
		if n.Type.Equal(appPublicAddrOID) {
			addr, ok := n.Value.(string)
			return ok && addr == host
		}
	}
	return false
}
