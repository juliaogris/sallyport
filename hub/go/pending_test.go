package main

import (
	"slices"
	"testing"
)

// noter returns an evict func that appends name to closed.
func noter(closed *[]string) func(name string) func() {
	return func(name string) func() {
		return func() { *closed = append(*closed, name) }
	}
}

func TestPendingCountsUntilTheTicketDrops(t *testing.T) {
	p := &pendingSet{}
	a, evicted := p.admit(2, "a", func() { t.Error("evicted a") })
	if evicted {
		t.Error("admit evicted with nothing waiting")
	}
	if got := p.waiting(); got != 1 {
		t.Errorf("waiting = %d, want 1", got)
	}
	a.drop()
	if got := p.waiting(); got != 0 {
		t.Errorf("waiting = %d after drop, want 0", got)
	}
}

func TestPendingEvictsTheOldestAtTheLimit(t *testing.T) {
	p := &pendingSet{}
	var closed []string
	note := noter(&closed)
	p.admit(2, "a", note("a1"))
	p.admit(2, "a", note("a2"))
	_, evicted := p.admit(2, "a", note("a3"))
	if !evicted {
		t.Error("admit at the limit evicted nothing")
	}
	if want := []string{"a1"}; !slices.Equal(closed, want) {
		t.Errorf("closed %v, want %v", closed, want)
	}
	if got := p.waiting(); got != 2 {
		t.Errorf("waiting = %d, want 2", got)
	}
}

func TestPendingEvictsTheClientWithTheMost(t *testing.T) {
	p := &pendingSet{}
	var closed []string
	note := noter(&closed)
	p.admit(3, "agent", note("agent"))
	p.admit(3, "x", note("x1"))
	p.admit(3, "x", note("x2"))
	_, evicted := p.admit(3, "x", note("x3"))
	if !evicted {
		t.Error("admit at the limit evicted nothing")
	}
	p.admit(3, "x", note("x4"))
	if want := []string{"x1", "x2"}; !slices.Equal(closed, want) {
		t.Errorf("closed %v, want %v", closed, want)
	}
}

func TestPendingTicketOfAnEvictedConnectionRemovesNothing(t *testing.T) {
	p := &pendingSet{}
	a, _ := p.admit(1, "a", func() {})
	p.admit(1, "a", func() {})
	a.drop()
	if got := p.waiting(); got != 1 {
		t.Errorf("waiting = %d, want 1", got)
	}
}

func TestClientKey(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"", ""},
		{"192.0.2.1", "192.0.2.1"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"::ffff:192.0.2.1", "0:0:0:0::/64"},
		{"not an ip", "not an ip"},
	}
	for _, tt := range tests {
		req := &request{header: map[string]string{"cf-connecting-ip": tt.ip}}
		if got := clientKey(req); got != tt.want {
			t.Errorf("clientKey(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}
