package main

import (
	"encoding/binary"
	"fmt"
	"time"
)

// maxHello is the most client bytes a frameTap keeps while it waits for
// a whole TLS ClientHello.
const maxHello = 16 << 10

// frameTap parses the WebSocket frames that one side sends, as an
// io.Writer that never fails. It logs control frames, and on the client
// side it logs the SNI and ALPN protocols of the first TLS ClientHello in
// the binary frames.
type frameTap struct {
	side  string
	logf  func(string, ...any)
	buf   []byte
	hello []byte
	done  bool
	pings int
	last  time.Time
	// payload is called with each unmasked data frame payload. It is for
	// tests, and may be nil.
	payload func(opcode byte, p []byte)
}

func newFrameTap(side string, logf func(string, ...any)) *frameTap {
	return &frameTap{side: side, logf: logf}
}

func (t *frameTap) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	for {
		n, ok := t.frame()
		if !ok {
			break
		}
		t.buf = t.buf[n:]
	}
	return len(p), nil
}

// frame handles the first frame in t.buf, if it is whole, and returns its
// length.
func (t *frameTap) frame() (int, bool) {
	b := t.buf
	if len(b) < 2 {
		return 0, false
	}
	opcode := b[0] & 0x0f
	masked := b[1]&0x80 != 0
	n := uint64(b[1] & 0x7f)
	off := 2
	switch n {
	case 126:
		if len(b) < off+2 {
			return 0, false
		}
		n = uint64(binary.BigEndian.Uint16(b[off:]))
		off += 2
	case 127:
		if len(b) < off+8 {
			return 0, false
		}
		n = binary.BigEndian.Uint64(b[off:])
		off += 8
	}
	var key []byte
	if masked {
		if len(b) < off+4 {
			return 0, false
		}
		key = b[off : off+4]
		off += 4
	}
	if uint64(len(b)-off) < n {
		return 0, false
	}
	end := off + int(n)
	payload := make([]byte, n)
	copy(payload, b[off:end])
	for i := range payload {
		if key != nil {
			payload[i] ^= key[i%4]
		}
	}
	t.handle(opcode, payload)
	return end, true
}

func (t *frameTap) handle(opcode byte, p []byte) {
	if t.payload != nil {
		t.payload(opcode, p)
	}
	switch opcode {
	case 0x0, 0x2:
		if t.side == "client" && !t.done {
			t.addHello(p)
		}
	case 0x1:
		t.logf("%s sent a text frame of %d bytes", t.side, len(p))
	case 0x8:
		t.logf("%s sent close %x", t.side, p)
	case 0x9:
		now := time.Now()
		gap := ""
		if !t.last.IsZero() {
			gap = fmt.Sprintf(", %v after the last", now.Sub(t.last).Round(time.Second))
		}
		t.pings++
		t.last = now
		t.logf("%s sent ping %d%s", t.side, t.pings, gap)
	case 0xa:
		t.logf("%s sent pong", t.side)
	}
}

func (t *frameTap) addHello(p []byte) {
	t.hello = append(t.hello, p...)
	h, err := parseClientHello(t.hello)
	switch {
	case err == errShort && len(t.hello) < maxHello:
		return
	case err != nil:
		t.logf("client hello: %v after %d bytes", err, len(t.hello))
	default:
		t.logf("client hello: sni %q alpn %q", h.sni, h.alpn)
	}
	t.done = true
	t.hello = nil
}
