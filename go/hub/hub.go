//go:build js && wasm

package main

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// memoryLimit is the Go soft memory limit. It counts only the memory
	// the Go runtime maps, which starts at about 4 MiB, on top of the
	// module's initial linear memory of about 38 MiB. The isolate has 128
	// MB for linear memory and the JavaScript heap together.
	memoryLimit = 48 << 20
	// heartbeatEvery is how often the hub logs its counters.
	heartbeatEvery = 60 * time.Second
)

// hub is the state of the one Durable Object. The Go program runs one hub
// per isolate.
type hub struct {
	cfg *config

	// tunnels counts open agent connections, for maxConnections.
	tunnels      atomic.Int64
	passthroughs atomic.Int64
	// lastDiscovery is the time of the last discovery request the agent
	// took, in Unix milliseconds, or 0 before the first one.
	lastDiscovery atomic.Int64

	appMu     sync.Mutex
	appTunnel *appTunnel

	pool *authPool
	auth *hubAuth
}

func newHub(env map[string]string) *hub {
	h := &hub{cfg: parseConfig(env), pool: &authPool{}}
	h.auth = &hubAuth{h: h}
	for _, err := range h.cfg.errs {
		logf("hub: config: %v", err)
	}
	logf("hub: go hub started, cluster %q", h.cfg.cluster)
	return h
}

// serve answers one request to the Durable Object.
func (h *hub) serve(req *request) (res *response) {
	defer func() {
		if p := recover(); p != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			logf("hub: panic serving %s %s: %v\n%s", req.method, req.path, p, buf)
			res = textError("internal error", 500)
		}
	}()
	special := false
	switch req.path {
	case "/webapi/find", "/webapi/ping", "/webapi/connectionupgrade", authPipePath:
		special = true
	}
	switch kind, name := h.cfg.classify(req.host); {
	case kind == hostApp:
		return h.appHostRequest(req, name)
	case kind == hostLogin && !special:
		return h.loginHostRequest(req)
	}
	if req.path == authPipePath {
		return h.acceptAuthPipe()
	}
	return h.acceptTunnel(req)
}

// heartbeat logs the hub's counters every heartbeatEvery, so that
// `wrangler tail` shows whether the object is alive, what it holds and how
// much memory it uses. It runs a GC first, which also frees the js.Values
// that only a finalizer releases.
func (h *hub) heartbeat() {
	for {
		time.Sleep(heartbeatEvery)
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		discovery := "never"
		if last := h.lastDiscovery.Load(); last != 0 {
			discovery = fmt.Sprintf("%ds ago", (time.Now().UnixMilli()-last)/1000)
		}
		h.appMu.Lock()
		app := "down"
		if h.appTunnel != nil {
			app = "up"
		}
		h.appMu.Unlock()
		open, ready := h.pool.counts()
		vals, valBytes := jsValues()
		logf("hub: heartbeat, %d tunnels, app tunnel %s, auth streams %d open %d ready, %d passthroughs, discovery %s, linear %s, heap %s, sys %s, gc %d, goroutines %d, js values %d (%s)",
			h.tunnels.Load(), app, open, ready, h.passthroughs.Load(), discovery,
			mib(uint64(linearMem())), mib(m.HeapAlloc), mib(m.Sys), m.NumGC, runtime.NumGoroutine(), vals, mib(uint64(valBytes)))
	}
}

func mib(b uint64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", float64(b)/(1<<20)), "0"), ".") + " MiB"
}
