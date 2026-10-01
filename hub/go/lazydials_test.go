package main

import "testing"

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

func TestDialTableCancelAfterTake(t *testing.T) {
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
	ch, _ = d.add("b", 2)
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
}
