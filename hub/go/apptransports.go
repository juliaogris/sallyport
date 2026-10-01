package main

import (
	"net/http"
	"sync"
	"time"
)

const (
	// maxAppTransports is the number of app sessions whose connections the
	// hub keeps. Above this the one used least recently is dropped.
	maxAppTransports = 32
	// appTransportIdle drops the transport of an app session that has sent
	// no request for this long.
	appTransportIdle = time.Minute
)

// appTransports holds one http.Transport per app session, so that the
// requests of one page share connections to the app service.
type appTransports struct {
	mu sync.Mutex
	m  map[string]*appTransport
}

type appTransport struct {
	tr   *http.Transport
	used time.Time
}

// get returns the transport of the app session sid, and makes it with
// newTr if there is none. Before it makes one, it drops the transports
// unused for appTransportIdle, and the least recently used one when
// maxAppTransports are kept, and closes their idle connections.
func (t *appTransports) get(sid string, now time.Time, newTr func() *http.Transport) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = make(map[string]*appTransport)
	}
	if e, ok := t.m[sid]; ok {
		e.used = now
		return e.tr
	}
	var oldest string
	for k, e := range t.m {
		if now.Sub(e.used) > appTransportIdle {
			e.tr.CloseIdleConnections()
			delete(t.m, k)
			continue
		}
		if oldest == "" || e.used.Before(t.m[oldest].used) {
			oldest = k
		}
	}
	if len(t.m) >= maxAppTransports {
		t.m[oldest].tr.CloseIdleConnections()
		delete(t.m, oldest)
	}
	tr := newTr()
	t.m[sid] = &appTransport{tr: tr, used: now}
	return tr
}
