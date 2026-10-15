//go:build js && wasm

package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall/js"
)

// glue holds the JavaScript functions of worker.mjs that Go calls. They are
// read once, so a call creates no new js.Value for the function.
var glue struct {
	accept, send, sendText, close, stream, chunk, linearMem, jsValues js.Value
	tokenUsed, tokenUse, dial, connected, readBody, cancelBody        js.Value
	acceptBrowser, wsSend                                             js.Value
}

var uint8Array = js.Global().Get("Uint8Array")

func main() {
	// The isolate has 128 MB for JavaScript and WASM together, and WASM
	// memory never shrinks. The soft limit makes the GC work harder before
	// the heap grows linear memory past it.
	debug.SetMemoryLimit(memoryLimit)

	g := js.Global().Get("sallyportGlue")
	for name, v := range map[string]*js.Value{
		"accept": &glue.accept, "send": &glue.send, "sendText": &glue.sendText,
		"close": &glue.close, "stream": &glue.stream, "chunk": &glue.chunk,
		"linearMem": &glue.linearMem, "jsValues": &glue.jsValues,
		"tokenUsed": &glue.tokenUsed, "tokenUse": &glue.tokenUse,
		"dial": &glue.dial, "connected": &glue.connected,
		"readBody": &glue.readBody, "cancelBody": &glue.cancelBody,
		"acceptBrowser": &glue.acceptBrowser, "wsSend": &glue.wsSend,
	} {
		*v = g.Get(name)
	}

	h := newHub(readEnv(js.Global().Get("sallyportEnv")))

	// One js.Func per entry point for the life of the program. The data
	// path passes only numbers, which need no js.Value.
	api := js.Global().Get("Object").New()
	api.Set("fetch", js.FuncOf(func(this js.Value, args []js.Value) any {
		req := readRequest(args[0])
		done := args[1]
		go func() {
			res := h.serve(req)
			res.send(done)
		}()
		return nil
	}))
	api.Set("push", js.FuncOf(func(this js.Value, args []js.Value) any {
		if c := conns.get(args[0].Int()); c != nil {
			c.pushIn(args[1].Int())
		}
		return nil
	}))
	api.Set("text", js.FuncOf(func(this js.Value, args []js.Value) any {
		if c := conns.get(args[0].Int()); c != nil {
			c.peerAck(args[1].String())
		}
		return nil
	}))
	api.Set("closed", js.FuncOf(func(this js.Value, args []js.Value) any {
		if c := conns.get(args[0].Int()); c != nil {
			c.remoteClosed(args[1].Int())
		}
		return nil
	}))
	api.Set("wsText", js.FuncOf(func(this js.Value, args []js.Value) any {
		if b := browserOf(args[0].Int()); b != nil {
			b.text(args[1].String())
		}
		return nil
	}))
	api.Set("wsBinary", js.FuncOf(func(this js.Value, args []js.Value) any {
		if b := browserOf(args[0].Int()); b != nil {
			b.binary(args[1].Int(), args[2].Bool())
		}
		return nil
	}))
	api.Set("wsClosed", js.FuncOf(func(this js.Value, args []js.Value) any {
		if b := browserOf(args[0].Int()); b != nil {
			b.browserClosed(args[1].Int(), args[2].String())
		}
		return nil
	}))
	api.Set("pull", js.FuncOf(func(this js.Value, args []js.Value) any {
		s := streams.get(args[0].Int())
		if s != nil {
			s.pull()
		}
		return s != nil
	}))
	api.Set("cancel", js.FuncOf(func(this js.Value, args []js.Value) any {
		if s := streams.get(args[0].Int()); s != nil {
			s.cancel()
		}
		return nil
	}))
	api.Set("bodyChunk", js.FuncOf(func(this js.Value, args []js.Value) any {
		bodyChunk(args[0].Int(), args[1].Int())
		return nil
	}))
	api.Set("refuse", js.FuncOf(func(this js.Value, args []js.Value) any {
		if h.lazy != nil {
			h.lazy.refuse(args[0].String())
		}
		return nil
	}))
	api.Set("diag", js.FuncOf(func(this js.Value, args []js.Value) any {
		return diagString()
	}))
	api.Set("shutdown", js.FuncOf(func(this js.Value, args []js.Value) any {
		logf("hub: shutting down for a new Durable Object instance")
		os.Exit(0)
		return nil
	}))
	js.Global().Set("sallyport", api)
	// The lazy hub starts no timers while idle, so that the object can
	// hibernate.
	if !h.cfg.lazy {
		go h.heartbeat()
	}
	select {}
}

// readEnv reads the vars and secrets the hub uses from the Durable
// Object's env.
func readEnv(env js.Value) map[string]string {
	out := make(map[string]string)
	for _, name := range envNames {
		if v := env.Get(name); v.Type() == js.TypeString {
			out[name] = v.String()
		}
	}
	return out
}

// readRequest copies the request object that worker.mjs built.
func readRequest(r js.Value) *request {
	req := &request{
		method: r.Get("method").String(),
		host:   r.Get("host").String(),
		path:   r.Get("path").String(),
		query:  r.Get("query").String(),
		header: make(map[string]string),
	}
	for _, line := range strings.Split(r.Get("headers").String(), "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok {
			req.header[k] = v
		}
	}
	if b := r.Get("body"); b.Truthy() {
		req.body = make([]byte, b.Get("length").Int())
		js.CopyBytesToGo(req.body, b)
	}
	if id := r.Get("bodyStream"); id.Truthy() {
		req.bodyReader = newReqBody(id.Int())
	}
	return req
}

// send hands the response to worker.mjs.
func (r *response) send(done js.Value) {
	var head strings.Builder
	for _, kv := range r.header {
		head.WriteString(kv[0])
		head.WriteString(": ")
		head.WriteString(kv[1])
		head.WriteByte('\n')
	}
	var body any
	if r.body != "" {
		body = r.body
	}
	flags := 0
	if r.manual {
		flags |= 1
	}
	if r.raw && r.body != "" {
		flags |= 2
	}
	ws, stream := js.Null(), js.Null()
	if r.ws != nil {
		ws = r.ws.client
	}
	if r.browser != nil {
		ws = r.browser.client
	}
	if r.stream != nil {
		stream = r.stream.js
	}
	done.Invoke(r.status, strings.TrimSuffix(head.String(), "\n"), body, flags, ws, stream)
}

// linearMem returns the size of WASM linear memory in bytes.
func linearMem() int { return glue.linearMem.Invoke().Int() }

// jsValues returns the number of JavaScript values Go holds a reference
// to, and the bytes in the typed arrays among them.
func jsValues() (int, int) {
	f := strings.Fields(glue.jsValues.Invoke().String())
	if len(f) != 2 {
		return 0, 0
	}
	n, _ := strconv.Atoi(f[0])
	b, _ := strconv.Atoi(f[1])
	return n, b
}

func logf(format string, args ...any) { fmt.Printf(format+"\n", args...) }
