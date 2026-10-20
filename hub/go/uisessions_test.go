package main

import (
	"testing"
	"time"
)

func TestUISessions(t *testing.T) {
	now := time.Unix(1000, 0)
	var u uiSessions

	u.put("a", "u", "w", now)
	got, ok := u.take("a", now)
	if !ok || got.user != "u" || got.sid != "w" {
		t.Fatalf("take(a) = %+v, %v", got, ok)
	}
	if _, ok := u.take("a", now); ok {
		t.Error("take(a) twice")
	}
	if _, ok := u.take("b", now); ok {
		t.Error("take(b) without put")
	}

	u.put("old", "u", "w", now)
	now = now.Add(uiSessionTTL)
	if _, ok := u.take("old", now); !ok {
		t.Error("take at uiSessionTTL after the launch")
	}
	u.put("old", "u", "w", now)
	now = now.Add(uiSessionTTL + time.Second)
	if _, ok := u.take("old", now); ok {
		t.Error("take after uiSessionTTL")
	}

	u.put("x", "u", "w", now)
	now = now.Add(uiSessionTTL + time.Second)
	u.put("y", "u", "w", now)
	if _, ok := u.m["x"]; ok || len(u.m) != 1 {
		t.Errorf("put kept an old entry: %v", u.m)
	}
}
