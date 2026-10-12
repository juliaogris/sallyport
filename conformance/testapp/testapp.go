// Package testapp is the app behind the hub in the conformance tests and
// the load runs. It serves generated responses of each kind a browser
// meets: static bodies, large and slow downloads, gzip, bodyless statuses,
// MJPEG streams, uploads, a page with many small assets, a SockJS-like
// stream of short lines, and a WebSocket echo.
//
// Every path starts with /t/. With a directory, other paths are served
// from it, so the app can replace a plain file server.
package testapp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Bodies the app serves.
var (
	StaticBody = []byte("hello from the app\n")
	GzipPlain  = []byte("hello, gzipped\n")
)

// CLTEPath is the path that answers with CLTEResponse.
const CLTEPath = "/t/clte"

// CLTEResponse has both Content-Length: 5 and Transfer-Encoding: chunked,
// and a chunked body of 26 bytes. A client must follow the chunked
// encoding (RFC 9112, section 6.3) and read CLTEBody.
const CLTEResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n" +
	"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
	"d\r\nabcdefghijklm\r\nd\r\nnopqrstuvwxyz\r\n0\r\n\r\n"

// CLTEBody is the body of CLTEResponse.
const CLTEBody = "abcdefghijklmnopqrstuvwxyz"

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
	// /t/slow?n=N&bps=B sends N bytes at B bytes per second. With len=1 it
	// sets Content-Length.
	mux.HandleFunc("/t/slow", func(w http.ResponseWriter, r *http.Request) {
		n, bps := intParam(r, "n", 64<<10), intParam(r, "bps", 16<<10)
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Query().Get("len") == "1" {
			w.Header().Set("Content-Length", strconv.Itoa(n))
		}
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
	// /t/clte answers with CLTEResponse. It hijacks the connection, so the
	// conn must support read deadlines.
	mux.HandleFunc("/t/clte", func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		buf.WriteString(CLTEResponse)
		buf.Flush()
		conn.Close()
	})
	// A 101 to a request without Upgrade, which no hub can forward. The
	// handler sets the status instead of hijacking, because Hijack waits
	// for the server's background read to end, and the agent's chanConn
	// has no read deadline to end it.
	mux.HandleFunc("/t/status/101", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
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
	// /t/quiet?secs=S sends nothing for S seconds, then answers 200, like a
	// long poll.
	mux.HandleFunc("/t/quiet", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Duration(intParam(r, "secs", 35)) * time.Second):
		}
		w.Write([]byte("done\n"))
	})
	// /t/upload counts the request body and returns the count. With
	// bps=B it reads B bytes per second, like an app that writes the
	// upload to a slow disk.
	mux.HandleFunc("POST /t/upload", func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if bps := intParam(r, "bps", 0); bps > 0 {
			body = &slowReader{r: r.Body, bps: bps}
		}
		n, err := io.Copy(io.Discard, body)
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
	// /t/drip?n=N&ms=M sends a SockJS-like stream: a 2 KiB prelude line,
	// then N short lines, one every M milliseconds, each flushed.
	mux.HandleFunc("/t/drip", func(w http.ResponseWriter, r *http.Request) {
		n, ms := intParam(r, "n", 8), intParam(r, "ms", 500)
		w.Header().Set("Content-Type", "application/javascript; charset=UTF-8")
		rc := http.NewResponseController(w)
		w.Write(append(bytes.Repeat([]byte("h"), 2048), '\n'))
		if rc.Flush() != nil {
			return
		}
		for i := range n {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
			fmt.Fprintf(w, "a[\"%d\"]\n", i)
			if rc.Flush() != nil {
				return
			}
		}
	})
	mux.HandleFunc("/t/ws", ws.serve)
	mux.HandleFunc("/t/wsclosed", ws.closed)
	return mux
}

// wsApp is the WebSocket endpoint of the app. It records the close code
// each socket got from its peer, by the id query parameter.
type wsApp struct {
	mu    sync.Mutex
	codes map[string]int
	cond  *sync.Cond
}

var ws = newWSApp()

func newWSApp() *wsApp {
	a := &wsApp{codes: make(map[string]int)}
	a.cond = sync.NewCond(&a.mu)
	return a
}

var upgrader = websocket.Upgrader{
	Subprotocols: []string{"chat"},
	// The hub checks the origin.
	CheckOrigin: func(*http.Request) bool { return true },
}

// serve answers /t/ws?id=I&hello=1. With hello=1 the first message is the
// handshake as an Echo in JSON. Then each message is echoed with its type,
// except two text commands: "close CODE REASON" closes the socket with
// that code and reason, and "big N" sends N bytes of Pattern as one binary
// message.
func (a *wsApp) serve(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 << 20)
	id := r.URL.Query().Get("id")
	if r.URL.Query().Get("hello") == "1" {
		client := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			client = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		b, _ := json.Marshal(Echo{Method: r.Method, Host: r.Host, URI: r.RequestURI, Header: r.Header, Client: client})
		if conn.WriteMessage(websocket.TextMessage, b) != nil {
			return
		}
	}
	for {
		typ, msg, err := conn.ReadMessage()
		if err != nil {
			code := websocket.CloseAbnormalClosure
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				code = ce.Code
			}
			a.mu.Lock()
			a.codes[id] = code
			a.cond.Broadcast()
			a.mu.Unlock()
			return
		}
		if typ == websocket.TextMessage {
			f := strings.SplitN(string(msg), " ", 3)
			switch {
			case f[0] == "close" && len(f) == 3:
				code, _ := strconv.Atoi(f[1])
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, f[2]), time.Now().Add(5*time.Second))
				// Waits for the peer's close, which ends the next read.
				continue
			case f[0] == "big" && len(f) == 2:
				n, _ := strconv.Atoi(f[1])
				if conn.WriteMessage(websocket.BinaryMessage, Pattern(n)) != nil {
					return
				}
				continue
			}
		}
		if conn.WriteMessage(typ, msg) != nil {
			return
		}
	}
}

// closed answers /t/wsclosed?id=I with the close code the socket I got
// from its peer, waiting up to 10 seconds for it, or 0.
func (a *wsApp) closed(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	t := time.AfterFunc(10*time.Second, func() {
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	})
	defer t.Stop()
	end := time.Now().Add(10 * time.Second)
	a.mu.Lock()
	code, ok := a.codes[id]
	for !ok && time.Now().Before(end) {
		a.cond.Wait()
		code, ok = a.codes[id]
	}
	a.mu.Unlock()
	fmt.Fprintf(w, "%d\n", code)
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

// slowReader reads at most bps bytes per second from r.
type slowReader struct {
	r   io.Reader
	bps int
}

func (s *slowReader) Read(p []byte) (int, error) {
	p = p[:min(len(p), max(s.bps/10, 1))]
	n, err := s.r.Read(p)
	time.Sleep(time.Duration(n) * time.Second / time.Duration(s.bps))
	return n, err
}
