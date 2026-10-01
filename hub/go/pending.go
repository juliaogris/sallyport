package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sync"
)

// pendingSet holds connections that have not proved who they are, oldest
// first. Each one holds a ticket until it has. At the cap, the client with
// the most connections waiting loses its oldest, so one client address that
// opens many connections evicts its own, not the agent's or auth's.
type pendingSet struct {
	mu    sync.Mutex
	next  uint64
	queue []pendingConn
}

// pendingConn is one connection waiting in a pendingSet.
type pendingConn struct {
	id     uint64
	client string
	evict  func()
}

// ticket is one connection's place in a pendingSet.
type ticket struct {
	id  uint64
	set *pendingSet
}

// admit adds a connection from client. evict closes the connection when a
// later admit evicts it. If limit connections are already waiting, admit
// first evicts the oldest connection of the client that has the most
// waiting, counting the new one. It returns the connection's ticket and
// whether it evicted another connection.
func (p *pendingSet) admit(limit int, client string, evict func()) (*ticket, bool) {
	var evicted []func()
	p.mu.Lock()
	// With a limit of 0 the loop would never end.
	for len(p.queue) >= max(limit, 1) {
		at := p.busiestOldest(client)
		evicted = append(evicted, p.queue[at].evict)
		p.queue = slices.Delete(p.queue, at, at+1)
	}
	t := &ticket{id: p.next, set: p}
	p.next++
	p.queue = append(p.queue, pendingConn{id: t.id, client: client, evict: evict})
	p.mu.Unlock()
	for _, f := range evicted {
		f()
	}
	return t, len(evicted) > 0
}

// busiestOldest returns the index of the oldest waiting connection whose
// client has the most connections waiting, counting a new one from client.
func (p *pendingSet) busiestOldest(client string) int {
	counts := map[string]int{client: 1}
	for _, c := range p.queue {
		counts[c.client]++
	}
	most := 0
	for _, n := range counts {
		most = max(most, n)
	}
	at := slices.IndexFunc(p.queue, func(c pendingConn) bool { return counts[c.client] == most })
	return max(at, 0)
}

// waiting returns the number of connections waiting.
func (p *pendingSet) waiting() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue)
}

// drop removes the connection from its pendingSet. It does nothing for a
// connection that was evicted.
func (t *ticket) drop() {
	t.set.mu.Lock()
	t.set.queue = slices.DeleteFunc(t.set.queue, func(c pendingConn) bool { return c.id == t.id })
	t.set.mu.Unlock()
}

// clientKey returns the client address of req from CF-Connecting-IP, with an
// IPv6 address cut to its /64, because one host usually holds a whole /64.
// It is empty when the header is missing, as under wrangler dev.
func clientKey(req *request) string {
	ip := req.header["cf-connecting-ip"]
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() {
		return ip
	}
	b := addr.As16()
	group := func(i int) uint16 { return binary.BigEndian.Uint16(b[i : i+2]) }
	return fmt.Sprintf("%x:%x:%x:%x::/64", group(0), group(2), group(4), group(6))
}
