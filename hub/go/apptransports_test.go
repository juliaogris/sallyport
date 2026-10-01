package main

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestAppTransports(t *testing.T) {
	now := time.Now()
	made := 0
	newTr := func() *http.Transport {
		made++
		return &http.Transport{}
	}
	var ts appTransports

	a := ts.get("a", now, newTr)
	if got := ts.get("a", now.Add(time.Second), newTr); got != a {
		t.Error("get made a second transport for one session")
	}
	if made != 1 {
		t.Errorf("made %d transports, want 1", made)
	}

	ts.get("b", now.Add(time.Second+appTransportIdle+time.Second), newTr)
	if _, ok := ts.m["a"]; ok {
		t.Error("get kept a transport unused for longer than appTransportIdle")
	}

	ts = appTransports{}
	first := ts.get("s0", now, newTr)
	for i := 1; i < maxAppTransports; i++ {
		ts.get(fmt.Sprintf("s%d", i), now.Add(time.Duration(i)*time.Millisecond), newTr)
	}
	ts.get("new", now.Add(time.Second), newTr)
	if len(ts.m) != maxAppTransports {
		t.Errorf("kept %d transports, want %d", len(ts.m), maxAppTransports)
	}
	if got := ts.get("s0", now.Add(time.Second), newTr); got == first {
		t.Error("the least recently used transport was kept above maxAppTransports")
	}
}
