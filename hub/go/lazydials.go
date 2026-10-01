package main

import "sync"

// dialTable holds the dials of the lazy hub that wait for their stream, by
// stream id. Each id is used once.
type dialTable[T any] struct {
	mu sync.Mutex
	m  map[string]chan T
}

// add registers a dial for id and returns the channel its stream arrives
// on. It returns false when max dials are already waiting.
func (t *dialTable[T]) add(id string, max int) (chan T, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= max {
		return nil, false
	}
	if t.m == nil {
		t.m = make(map[string]chan T)
	}
	ch := make(chan T, 1)
	t.m[id] = ch
	return ch, true
}

// take removes the dial for id and returns its channel. The caller must
// send the stream on it, which does not block. It returns false when no
// dial waits for id.
func (t *dialTable[T]) take(id string) (chan T, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch, ok := t.m[id]
	delete(t.m, id)
	return ch, ok
}

// cancel removes the dial for id. It returns false when take already
// removed it, and then the stream arrives on the dial's channel.
func (t *dialTable[T]) cancel(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.m[id]
	delete(t.m, id)
	return ok
}
