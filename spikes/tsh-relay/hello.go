package main

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// errShort means that the bytes so far do not hold a whole ClientHello.
var errShort = errors.New("short client hello")

// clientHello holds the fields of a TLS ClientHello that the spike logs.
type clientHello struct {
	sni  string
	alpn []string
}

// parseClientHello parses the TLS ClientHello at the start of b, which may
// span several TLS records. It returns errShort if b ends before the
// ClientHello does.
func parseClientHello(b []byte) (clientHello, error) {
	var hs []byte
	for len(b) > 0 {
		if len(b) < 5 {
			return clientHello{}, errShort
		}
		if b[0] != 0x16 {
			return clientHello{}, fmt.Errorf("record type %d is not handshake", b[0])
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			return clientHello{}, errShort
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
		if len(hs) >= 4 && len(hs) >= 4+int(hs[1])<<16|int(hs[2])<<8|int(hs[3]) {
			break
		}
	}
	if len(hs) < 4 {
		return clientHello{}, errShort
	}
	if hs[0] != 1 {
		return clientHello{}, fmt.Errorf("handshake type %d is not client hello", hs[0])
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return clientHello{}, errShort
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
		case 16: // application_layer_protocol_negotiation
			list := reader(data.bytes(int(data.u16())))
			for len(list.b) > 0 && list.err == nil {
				h.alpn = append(h.alpn, string(list.bytes(int(list.u8()))))
			}
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

// tlsRoots is a set of root certificates for the relay's upstream dial.
// A nil *tlsRoots means the system roots.
type tlsRoots struct{ p *x509.CertPool }

func (r *tlsRoots) pool() *x509.CertPool {
	if r == nil {
		return nil
	}
	return r.p
}
