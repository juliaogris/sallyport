package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The passkeys page draws the QR code of a link with its own encoder. These
// tests run that encoder under node and decode what it draws, and check
// the decoder itself against qrencode.

// qrLevelM is the codeword layout of error correction level M by version:
// total codewords, error correction codewords per block, and blocks.
var qrLevelM = [][3]int{{26, 10, 1}, {44, 16, 1}, {70, 26, 1}, {100, 18, 2}, {134, 24, 2}, {172, 16, 4}}

func TestPageQR(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name, text string
		size       int
	}{
		{"short", "hello", 21},
		{"go link", "https://go.example.com/web/add-passkey/" + token, 37},
		{"edge link", "https://julia.example.com/web/add-passkey/" + token, 37},
		{"four blocks", strings.Repeat("sallyport ", 10), 41},
		{"longest", strings.Repeat("x", 106), 41},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := pageQR(t, c.text)
			if err != nil {
				t.Fatal(err)
			}
			if len(m) != c.size {
				t.Errorf("size %d, want %d", len(m), c.size)
			}
			got, err := decodeQR(m)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.text {
				t.Errorf("decoded %q, want %q", got, c.text)
			}
		})
	}
	t.Run("too long", func(t *testing.T) {
		_, err := pageQR(t, strings.Repeat("x", 107))
		if err == nil || !strings.Contains(err.Error(), "too long") {
			t.Errorf("err = %v, want too long", err)
		}
	})
	t.Run("flipped modules", func(t *testing.T) {
		m, err := pageQR(t, "hello")
		if err != nil {
			t.Fatal(err)
		}
		m[20][20] ^= 1
		if _, err := decodeQR(m); err == nil || !strings.Contains(err.Error(), "syndrome") {
			t.Errorf("flipped data module: err = %v, want a syndrome error", err)
		}
		m[20][20] ^= 1
		m[3][3] ^= 1
		if _, err := decodeQR(m); err == nil || !strings.Contains(err.Error(), "function patterns") {
			t.Errorf("flipped finder module: err = %v, want a function pattern error", err)
		}
	})
}

// TestDecodeQRAgainstQrencode checks the decoder on codes from qrencode,
// which picks the mask with the lowest penalty, so the decoder sees masks
// other than 0.
func TestDecodeQRAgainstQrencode(t *testing.T) {
	qrencode, err := exec.LookPath("qrencode")
	if err != nil {
		t.Skip("qrencode not installed")
	}
	texts := []string{"hello", "https://go.example.com/web/add-passkey/0123456789abcdef0123456789abcdef", strings.Repeat("sallyport ", 10)}
	for _, text := range texts {
		out, err := exec.CommandContext(t.Context(), qrencode, "-8", "-l", "M", "-m", "0", "-t", "ASCII", "-o", "-", text).Output()
		if err != nil {
			t.Fatal(err)
		}
		var m [][]int
		for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			var row []int
			for i := 0; i < len(line); i += 2 {
				bit := 0
				if line[i] == '#' {
					bit = 1
				}
				row = append(row, bit)
			}
			m = append(m, row)
		}
		got, err := decodeQR(m)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if got != text {
			t.Errorf("decoded %q, want %q", got, text)
		}
	}
}

// pageQR runs the encoder of the passkeys page, its first script block,
// under node for text and returns the modules it draws.
func pageQR(t *testing.T, text string) ([][]int, error) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	start := strings.Index(passkeysPage, "<script>")
	end := strings.Index(passkeysPage, "</script>")
	if start < 0 || end < start {
		t.Fatal("no script block in the passkeys page")
	}
	script := passkeysPage[start+len("<script>"):end] + "\nconsole.log(JSON.stringify(qr(process.argv[2])));\n"
	path := filepath.Join(t.TempDir(), "qr.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), node, path, text).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil, fmt.Errorf("node: %s", exit.Stderr)
	}
	if err != nil {
		return nil, err
	}
	var m [][]int
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("node output: %w", err)
	}
	return m, nil
}

// decodeQR reads the byte mode text of a QR code of version 1 to 6 with
// error correction level M. It checks the function patterns, both copies
// of the format information and its BCH code, the Reed-Solomon codewords
// of every block, and the terminator and padding after the text.
func decodeQR(m [][]int) (string, error) {
	n := len(m)
	v := (n - 17) / 4
	if v < 1 || v > 6 || n != 17+4*v {
		return "", fmt.Errorf("%d rows is no version 1 to 6", n)
	}
	function := make([][]bool, n)
	for r, row := range m {
		if len(row) != n {
			return "", fmt.Errorf("row %d has %d modules, want %d", r, len(row), n)
		}
		function[r] = make([]bool, n)
	}
	var errs []string
	check := func(r, c int, dark bool) {
		function[r][c] = true
		if (m[r][c] == 1) != dark {
			errs = append(errs, fmt.Sprintf("(%d,%d) is %d", r, c, m[r][c]))
		}
	}
	for _, p := range [][2]int{{0, 0}, {0, n - 7}, {n - 7, 0}} {
		for dr := -1; dr < 8; dr++ {
			for dc := -1; dc < 8; dc++ {
				r, c := p[0]+dr, p[1]+dc
				if r < 0 || r >= n || c < 0 || c >= n {
					continue
				}
				inside := dr >= 0 && dr < 7 && dc >= 0 && dc < 7
				check(r, c, inside && max(abs(dr-3), abs(dc-3)) != 2)
			}
		}
	}
	for i := 8; i < n-8; i++ {
		check(6, i, i%2 == 0)
		check(i, 6, i%2 == 0)
	}
	check(n-8, 8, true)
	if v > 1 {
		for dr := -2; dr < 3; dr++ {
			for dc := -2; dc < 3; dc++ {
				check(n-7+dr, n-7+dc, max(abs(dr), abs(dc)) != 1)
			}
		}
	}
	if len(errs) > 0 {
		return "", fmt.Errorf("function patterns: %s", strings.Join(errs, ", "))
	}

	var first, second int
	for i := 0; i < 15; i++ {
		var r, c int
		switch {
		case i < 6:
			r, c = i, 8
		case i < 8:
			r, c = i+1, 8
		case i == 8:
			r, c = 8, 7
		default:
			r, c = 8, 14-i
		}
		first |= m[r][c] << i
		function[r][c] = true
		if i < 8 {
			r, c = 8, n-1-i
		} else {
			r, c = n-15+i, 8
		}
		second |= m[r][c] << i
		function[r][c] = true
	}
	if first != second {
		return "", fmt.Errorf("format copies differ: %015b and %015b", first, second)
	}
	format := first ^ 0x5412
	rem := format
	for i := 14; i >= 10; i-- {
		if rem>>i&1 == 1 {
			rem ^= 0x537 << (i - 10)
		}
	}
	if rem != 0 {
		return "", fmt.Errorf("format %015b fails its BCH check", format)
	}
	if level := format >> 13; level != 0 {
		return "", fmt.Errorf("error correction level bits %02b, want 00 for M", level)
	}
	mask := format >> 10 & 7

	var bits []int
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				c := right - j
				r := vert
				if (right+1)&2 == 0 {
					r = n - 1 - vert
				}
				if function[r][c] {
					continue
				}
				bit := m[r][c]
				if qrMasked(mask, r, c) {
					bit ^= 1
				}
				bits = append(bits, bit)
			}
		}
	}
	total, ecLen, blocks := qrLevelM[v-1][0], qrLevelM[v-1][1], qrLevelM[v-1][2]
	if len(bits) < total*8 {
		return "", fmt.Errorf("%d data bits, want at least %d", len(bits), total*8)
	}
	for _, b := range bits[total*8:] {
		if b != 0 {
			return "", fmt.Errorf("a remainder bit is set")
		}
	}
	cw := make([]int, total)
	for i := range cw {
		for _, b := range bits[i*8 : i*8+8] {
			cw[i] = cw[i]<<1 | b
		}
	}
	per := (total - ecLen*blocks) / blocks
	var data []int
	for b := 0; b < blocks; b++ {
		block := make([]int, 0, per+ecLen)
		for i := 0; i < per; i++ {
			block = append(block, cw[i*blocks+b])
		}
		for i := 0; i < ecLen; i++ {
			block = append(block, cw[per*blocks+i*blocks+b])
		}
		if err := rsCheck(block, ecLen); err != nil {
			return "", fmt.Errorf("block %d: %w", b, err)
		}
		data = append(data, block[:per]...)
	}

	read := func(pos, k int) int {
		val := 0
		for i := pos; i < pos+k; i++ {
			val = val<<1 | data[i/8]>>(7-i%8)&1
		}
		return val
	}
	if mode := read(0, 4); mode != 4 {
		return "", fmt.Errorf("mode %04b, want byte mode", mode)
	}
	count := read(4, 8)
	if 12+count*8 > len(data)*8 {
		return "", fmt.Errorf("%d bytes do not fit in %d data codewords", count, len(data))
	}
	text := make([]byte, count)
	for i := range text {
		text[i] = byte(read(12+i*8, 8))
	}
	pos := 12 + count*8
	for end := min(pos+4, len(data)*8); pos < end || pos%8 != 0; pos++ {
		if read(pos, 1) != 0 {
			return "", fmt.Errorf("bit %d after the text is set", pos)
		}
	}
	for i, pad := pos/8, 0xec; i < len(data); i, pad = i+1, pad^0xfd {
		if data[i] != pad {
			return "", fmt.Errorf("padding codeword %d is %#x, want %#x", i, data[i], pad)
		}
	}
	return string(text), nil
}

// qrMasked reports whether the data module at (r, c) is inverted by mask.
func qrMasked(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	default:
		return ((r+c)%2+(r*c)%3)%2 == 0
	}
}

// gfExp and gfLog are the exponent and log tables of GF(256) with the QR
// code polynomial 0x11d.
var gfExp, gfLog = func() ([255]int, [256]int) {
	var exp [255]int
	var log [256]int
	x := 1
	for i := range exp {
		exp[i] = x
		log[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	return exp, log
}()

func gfMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(gfLog[a]+gfLog[b])%255]
}

// rsCheck reports an error unless the codewords of one block, the data
// then the error correction, form a multiple of the generator polynomial,
// which is zero at α^0 to α^(ecLen-1).
func rsCheck(block []int, ecLen int) error {
	for i := range ecLen {
		acc := 0
		for _, b := range block {
			acc = gfMul(acc, gfExp[i]) ^ b
		}
		if acc != 0 {
			return fmt.Errorf("syndrome %d is %d, want 0", i, acc)
		}
	}
	return nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
