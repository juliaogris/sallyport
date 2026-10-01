package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// errDialRefused is the error of a lazy dial that auth's callout answered
// with "refuse <id>", for example because it has too many streams open.
var errDialRefused = errors.New("auth's callout refused the stream")

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

// wait waits for the stream of the dial for id, which add returned ch for,
// for up to d or until ctx ends. The error names kind. A stream that
// arrives as the wait gives up is returned with no error.
func (t *dialTable[T]) wait(ctx context.Context, id string, ch chan T, d time.Duration, kind string) (T, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v, nil
	case <-timer.C:
		if !t.cancel(id) {
			return <-ch, nil
		}
		var zero T
		return zero, fmt.Errorf("no %s stream within %v", kind, d)
	case <-ctx.Done():
		if !t.cancel(id) {
			return <-ch, nil
		}
		var zero T
		return zero, fmt.Errorf("%s dial: %w", kind, ctx.Err())
	}
}
