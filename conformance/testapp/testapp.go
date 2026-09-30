// Package testapp is the app behind the hub in the conformance tests and
// the load runs. It serves generated responses of each kind a browser
// meets: static bodies, large and slow downloads, gzip, bodyless statuses,
// MJPEG streams, uploads, and a page with many small assets.
//
// Every path starts with /t/. With a directory, other paths are served
// from it, so the app can replace a plain file server.
package testapp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Bodies the app serves.
var (
	StaticBody = []byte("hello from the app\n")
	GzipPlain  = []byte("hello, gzipped\n")
)

// Echo is what /t/echo returns.
type Echo struct {
	Method string
	Host   string
	URI    string
	Header http.Header
	Body   string
	// Client is the common name of the TLS client certificate, or "".
	Client string
}

// Handler returns the app. If dir is not empty, paths outside /t/ are
// served from dir.
func Handler(dir string) http.Handler {
	mux := http.NewServeMux()
	if dir != "" {
		mux.Handle("/", http.FileServer(http.Dir(dir)))
	}
	mux.HandleFunc("/t/static", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(StaticBody)))
		w.Write(StaticBody)
	})
	// /t/bytes?n=N sends N bytes without a Content-Length. With len=1 it
	// sets Content-Length.
	mux.HandleFunc("/t/bytes", func(w http.ResponseWriter, r *http.Request) {
		n := intParam(r, "n", 1<<20)
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Query().Get("len") == "1" {
			w.Header().Set("Content-Length", strconv.Itoa(n))
		}
		writePattern(w, n, 0, 0)
	})
	// /t/slow?n=N&bps=B sends N bytes at B bytes per second.
	mux.HandleFunc("/t/slow", func(w http.ResponseWriter, r *http.Request) {
		n, bps := intParam(r, "n", 64<<10), intParam(r, "bps", 16<<10)
		w.Header().Set("Content-Type", "application/octet-stream")
		writePattern(w, n, bps, 4<<10)
	})
	mux.HandleFunc("/t/gzip", func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write(GzipPlain)
		zw.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
		w.Write(b.Bytes())
	})
	for _, code := range []int{204, 205, 304} {
		mux.HandleFunc(fmt.Sprintf("/t/status/%d", code), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(code)
		})
	}
	// A 101 to a request without Upgrade, which no hub can forward.
	mux.HandleFunc("/t/status/101", func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		conn.Close()
	})
	mux.HandleFunc("/t/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		client := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			client = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Echo{
			Method: r.Method, Host: r.Host, URI: r.RequestURI,
			Header: r.Header, Body: string(body), Client: client,
		})
	})
	mux.HandleFunc("/t/setcookie", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "__Host-sp_app=evil; Path=/; Secure")
		w.Header().Add("Set-Cookie", "__Host-sp_subject=evil; Path=/; Secure")
		w.Header().Add("Set-Cookie", "app=1; Path=/")
		w.WriteHeader(http.StatusOK)
	})
	// /t/upload counts the request body and returns the count.
	mux.HandleFunc("POST /t/upload", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%d\n", n)
	})
	// /t/mjpeg?fps=F&secs=S sends a multipart JPEG-like stream of 20 KiB
	// frames, like a webcam. With secs=0 it runs until the client leaves.
	mux.HandleFunc("/t/mjpeg", func(w http.ResponseWriter, r *http.Request) {
		fps, secs := intParam(r, "fps", 10), intParam(r, "secs", 0)
		w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
		frame := bytes.Repeat([]byte{0xff}, 20<<10)
		rc := http.NewResponseController(w)
		tick := time.NewTicker(time.Second / time.Duration(max(fps, 1)))
		defer tick.Stop()
		end := time.Now().Add(time.Duration(secs) * time.Second)
		for secs == 0 || time.Now().Before(end) {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
			}
			fmt.Fprintf(w, "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(frame))
			w.Write(frame)
			w.Write([]byte("\r\n"))
			if rc.Flush() != nil {
				return
			}
		}
	})
	// /t/page is an HTML page with 50 assets of 2 to 20 KiB, like a web UI.
	mux.HandleFunc("/t/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><title>page</title>\n")
		for i := range PageAssets {
			fmt.Fprintf(w, "<img src=\"/t/asset/%d\">\n", i)
		}
	})
	mux.HandleFunc("/t/asset/{i}", func(w http.ResponseWriter, r *http.Request) {
		i, err := strconv.Atoi(r.PathValue("i"))
		if err != nil || i < 0 || i >= PageAssets {
			http.NotFound(w, r)
			return
		}
		n := AssetSize(i)
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Header().Set("Cache-Control", "no-store")
		writePattern(w, n, 0, 0)
	})
	return mux
}

// PageAssets is the number of assets on /t/page.
const PageAssets = 50

// AssetSize returns the size of asset i on /t/page.
func AssetSize(i int) int { return 2<<10 + (i*7919)%(18<<10) }

// Pattern returns the n bytes that /t/bytes?n=n sends.
func Pattern(n int) []byte {
	var b bytes.Buffer
	writePattern(&b, n, 0, 0)
	return b.Bytes()
}

// writePattern writes n bytes of a repeating pattern. With bps above 0 it
// writes chunk bytes at a time at bps bytes per second and flushes each.
func writePattern(w io.Writer, n, bps, chunk int) {
	buf := make([]byte, 64<<10)
	for i := range buf {
		buf[i] = byte(i)
	}
	if chunk == 0 {
		chunk = len(buf)
	}
	var rc *http.ResponseController
	if rw, ok := w.(http.ResponseWriter); ok && bps > 0 {
		rc = http.NewResponseController(rw)
	}
	for n > 0 {
		k := min(n, chunk, len(buf))
		if _, err := w.Write(buf[:k]); err != nil {
			return
		}
		n -= k
		if rc != nil {
			if rc.Flush() != nil {
				return
			}
			time.Sleep(time.Duration(k) * time.Second / time.Duration(bps))
		}
	}
}

func intParam(r *http.Request, name string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v < 0 {
		return def
	}
	return v
}
