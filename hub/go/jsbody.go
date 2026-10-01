//go:build js && wasm

package main

import (
	"errors"
	"io"
	"sync"
	"syscall/js"
)

// errBodyGone is the error of a request body whose JavaScript stream has
// gone, for example because the program is shutting down.
var errBodyGone = errors.New("request body gone")

// reqBody is a request body that Go reads from JavaScript as it arrives.
// Each Read asks worker.mjs for the next chunk with glue.readBody, and
// worker.mjs answers through bodyChunk into one persistent Uint8Array.
type reqBody struct {
	id     int
	buf    js.Value
	tmp    []byte
	rest   []byte
	err    error
	chunks chan int
	gone   chan struct{}
	once   sync.Once
}

// bodyChunkLast and bodyChunkError are the sizes bodyChunk passes for the
// end of the body and for a failed read.
const (
	bodyChunkLast  = -1
	bodyChunkError = -2
)

var reqBodies = struct {
	mu sync.Mutex
	m  map[int]*reqBody
}{m: make(map[int]*reqBody)}

// newReqBody returns the body that worker.mjs holds as request body id.
func newReqBody(id int) *reqBody {
	b := &reqBody{
		id:     id,
		buf:    uint8Array.New(inBytes),
		tmp:    make([]byte, inBytes),
		chunks: make(chan int, 1),
		gone:   make(chan struct{}),
	}
	reqBodies.mu.Lock()
	reqBodies.m[id] = b
	reqBodies.mu.Unlock()
	return b
}

// bodyChunk delivers the answer to one glue.readBody of body id: n > 0
// bytes in its buffer, bodyChunkLast or bodyChunkError. It runs inside a
// JavaScript callback, so it must not block.
func bodyChunk(id, n int) {
	reqBodies.mu.Lock()
	b := reqBodies.m[id]
	reqBodies.mu.Unlock()
	if b == nil {
		return
	}
	select {
	case b.chunks <- n:
	default:
	}
}

func (b *reqBody) Read(p []byte) (int, error) {
	if len(b.rest) > 0 {
		n := copy(p, b.rest)
		b.rest = b.rest[n:]
		return n, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	if !glue.readBody.Invoke(b.id, b.buf).Bool() {
		b.err = errBodyGone
		return 0, b.err
	}
	var n int
	select {
	case n = <-b.chunks:
	case <-b.gone:
		b.err = errBodyGone
		return 0, b.err
	}
	switch {
	case n == bodyChunkLast:
		b.err = io.EOF
		return 0, b.err
	case n < 0:
		b.err = errors.New("request body: read failed")
		return 0, b.err
	}
	js.CopyBytesToGo(b.tmp[:n], b.buf)
	b.rest = b.tmp[:n]
	return b.Read(p)
}

// Close stops reading the body and tells worker.mjs to cancel its stream.
func (b *reqBody) Close() error {
	b.once.Do(func() {
		reqBodies.mu.Lock()
		delete(reqBodies.m, b.id)
		reqBodies.mu.Unlock()
		close(b.gone)
		glue.cancelBody.Invoke(b.id)
	})
	return nil
}
