package main

import "testing"

// add adds a verified stream to p as challenge would. It returns the stream
// and whether the pool closed another one.
func add(t *testing.T, p *authPool) (*wsConn, bool) {
	t.Helper()
	c := &wsConn{}
	return c, p.push(c)
}

func TestAuthPoolTakeSkipsClosedStreams(t *testing.T) {
	p := &authPool{}
	a, _ := add(t, p)
	b, _ := add(t, p)
	a.CloseWith(1000, "closed")
	if _, ready := p.counts(); ready != 1 {
		t.Errorf("ready = %d, want 1", ready)
	}
	if got := p.take(); got != b {
		t.Errorf("take = %v, want the open stream", got)
	}
	if got := p.take(); got != nil {
		t.Errorf("take = %v, want nil", got)
	}
}

func TestAuthPoolClosesOldestWaitingStreamAboveLimit(t *testing.T) {
	p := &authPool{}
	var streams []*wsConn
	for range maxAuthStreams {
		c, closed := add(t, p)
		if closed {
			t.Fatalf("closed a stream with %d open", len(streams)+1)
		}
		streams = append(streams, c)
	}
	newest, closed := add(t, p)
	if !closed {
		t.Fatal("kept every stream with more than maxAuthStreams open")
	}
	if !streams[0].isClosed() {
		t.Error("oldest stream still open")
	}
	for i, c := range streams[1:] {
		if c.isClosed() {
			t.Errorf("stream %d closed", i+1)
		}
	}
	if newest.isClosed() {
		t.Error("newest stream closed")
	}
	open, ready := p.counts()
	if open != maxAuthStreams+1 || ready != maxAuthStreams {
		t.Errorf("counts = %d open %d ready, want %d open %d ready", open, ready, maxAuthStreams+1, maxAuthStreams)
	}
}

func TestAuthPoolKeepsTheOnlyWaitingStream(t *testing.T) {
	p := &authPool{}
	for range maxAuthStreams {
		add(t, p)
		if p.take() == nil {
			t.Fatal("take = nil")
		}
	}
	c, closed := add(t, p)
	if closed || c.isClosed() {
		t.Error("closed the only waiting stream")
	}
	if _, ready := p.counts(); ready != 1 {
		t.Errorf("ready = %d, want 1", ready)
	}
}

func TestAuthPoolIsFullAtTwiceTheStreamLimit(t *testing.T) {
	p := &authPool{}
	for i := range maxAccepted {
		if p.full() {
			t.Fatalf("full with %d streams in use", i)
		}
		add(t, p)
		if p.take() == nil {
			t.Fatal("take = nil")
		}
	}
	if !p.full() {
		t.Errorf("not full with %d streams in use", maxAccepted)
	}
	p.release()
	if p.full() {
		t.Error("full after a release")
	}
}
