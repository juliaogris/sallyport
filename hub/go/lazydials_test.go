package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDialTableUsesEachIDOnce(t *testing.T) {
	var d dialTable[int]
	ch, ok := d.add("a", 2)
	if !ok {
		t.Fatal("add refused the first dial")
	}
	got, ok := d.take("a")
	if !ok {
		t.Fatal("take found no dial for a")
	}
	got <- 7
	if v := <-ch; v != 7 {
		t.Errorf("dial got %d, want 7", v)
	}
	if _, ok := d.take("a"); ok {
		t.Error("take found a dial for a used id")
	}
	if _, ok := d.take("b"); ok {
		t.Error("take found a dial for an unknown id")
	}
}

func TestDialTableRefusesAboveMax(t *testing.T) {
	var d dialTable[int]
	d.add("a", 2)
	d.add("b", 2)
	if _, ok := d.add("c", 2); ok {
		t.Error("add accepted a third dial with max 2")
	}
	d.cancel("a")
	if _, ok := d.add("c", 2); !ok {
		t.Error("add refused a dial after a cancel")
	}
}

func TestDialTableCancel(t *testing.T) {
	t.Run("after take", func(t *testing.T) {
		var d dialTable[int]
		ch, _ := d.add("a", 2)
		got, _ := d.take("a")
		got <- 7
		if d.cancel("a") {
			t.Error("cancel removed a dial that take had removed")
		}
		if v := <-ch; v != 7 {
			t.Errorf("dial got %d, want 7", v)
		}
	})
	t.Run("waiting dial", func(t *testing.T) {
		var d dialTable[int]
		ch, _ := d.add("b", 2)
		if !d.cancel("b") {
			t.Error("cancel did not remove a waiting dial")
		}
		if _, ok := d.take("b"); ok {
			t.Error("take found a cancelled dial")
		}
		select {
		case <-ch:
			t.Error("a cancelled dial got a stream")
		default:
		}
	})
}

func TestDialTableWait(t *testing.T) {
	t.Run("stream arrives", func(t *testing.T) {
		var d dialTable[int]
		ch, _ := d.add("a", 2)
		got, _ := d.take("a")
		got <- 7
		v, err := d.wait(context.Background(), "a", ch, time.Hour, "app")
		if err != nil || v != 7 {
			t.Errorf("wait = %d, %v, want 7, nil", v, err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		var d dialTable[int]
		ch, _ := d.add("a", 2)
		_, err := d.wait(context.Background(), "a", ch, time.Millisecond, "app")
		if err == nil {
			t.Fatal("wait returned no error after its deadline")
		}
		if _, ok := d.take("a"); ok {
			t.Error("the dial is still waiting after its deadline")
		}
	})
	t.Run("context ends", func(t *testing.T) {
		var d dialTable[int]
		ch, _ := d.add("a", 2)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := d.wait(ctx, "a", ch, time.Hour, "auth")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("wait error = %v, want context.Canceled", err)
		}
		if _, ok := d.take("a"); ok {
			t.Error("the dial is still waiting after its context ended")
		}
	})
	t.Run("stream taken as the context ends", func(t *testing.T) {
		var d dialTable[int]
		ch, _ := d.add("a", 2)
		got, _ := d.take("a")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		go func() { got <- 7 }()
		v, err := d.wait(ctx, "a", ch, time.Hour, "app")
		if err != nil || v != 7 {
			t.Errorf("wait = %d, %v, want 7, nil", v, err)
		}
	})
}
