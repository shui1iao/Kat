package ss

import (
	"container/heap"
	"crypto/cipher"
	"net/netip"
	"time"
)

type saltEntry struct {
	key     string
	expires time.Time
}
type saltHeap []saltEntry

func (h saltHeap) Len() int           { return len(h) }
func (h saltHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h saltHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *saltHeap) Push(v any)        { *h = append(*h, v.(saltEntry)) }
func (h *saltHeap) Pop() any {
	a := *h
	v := a[len(a)-1]
	a[len(a)-1] = saltEntry{}
	*h = a[:len(a)-1]
	return v
}

type saltStore struct {
	entries  map[string]time.Time
	queue    saltHeap
	capacity int
}

func (c *saltStore) init(capacity int) { c.capacity = capacity; c.entries = make(map[string]time.Time) }
func (c *saltStore) expire(now time.Time) {
	for len(c.queue) > 0 && !c.queue[0].expires.After(now) {
		e := heap.Pop(&c.queue).(saltEntry)
		delete(c.entries, e.key)
	}
}
func (c *saltStore) admit(salt []byte, now time.Time) error {
	c.expire(now)
	k := string(salt)
	if _, exists := c.entries[k]; exists {
		return ErrReplay
	}
	if len(c.entries) >= c.capacity {
		return ErrCapacity
	}
	exp := now.Add(replayTTL)
	c.entries[k] = exp
	heap.Push(&c.queue, saltEntry{k, exp})
	return nil
}

// A fixed 1024-packet window. Bit d records maxID-d. No false positives.
const udpWindowSize = 1024

type packetWindow struct {
	seen bool
	max  uint64
	bits [udpWindowSize / 64]uint64
}

func (w *packetWindow) accept(id uint64) bool {
	if !w.seen {
		w.seen = true
		w.max = id
		w.bits[0] = 1
		return true
	}
	if id > w.max {
		delta := id - w.max
		if delta >= udpWindowSize {
			clear(w.bits[:])
		} else {
			words := int(delta / 64)
			shift := uint(delta % 64)
			for i := len(w.bits) - 1; i >= 0; i-- {
				var v uint64
				j := i - words
				if j >= 0 {
					v = w.bits[j] << shift
					if shift > 0 && j > 0 {
						v |= w.bits[j-1] >> (64 - shift)
					}
				}
				w.bits[i] = v
			}
		}
		w.max = id
		w.bits[0] |= 1
		return true
	}
	d := w.max - id
	if d >= udpWindowSize {
		return false
	}
	mask := uint64(1) << (d % 64)
	i := d / 64
	if w.bits[i]&mask != 0 {
		return false
	}
	w.bits[i] |= mask
	return true
}

type udpSession struct {
	clientID, serverID, nextPacket uint64
	exhausted                      bool
	peer                           netip.AddrPort
	window                         packetWindow
	expires                        time.Time
	index                          int
	responseAEAD                   cipher.AEAD
	// requestAEAD is the client-session subkey AEAD, derived once from
	// key+clientID after the first authenticated packet created the session.
	requestAEAD cipher.AEAD
}
type sessionHeap []*udpSession

func (h sessionHeap) Len() int           { return len(h) }
func (h sessionHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h sessionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *sessionHeap) Push(v any)        { s := v.(*udpSession); s.index = len(*h); *h = append(*h, s) }
func (h *sessionHeap) Pop() any {
	a := *h
	s := a[len(a)-1]
	a[len(a)-1] = nil
	*h = a[:len(a)-1]
	s.index = -1
	return s
}

type sessionStore struct {
	entries   map[uint64]*udpSession
	serverIDs map[uint64]bool
	queue     sessionHeap
	capacity  int
	idle      time.Duration
}

func (c *sessionStore) init(n int) {
	c.entries = make(map[uint64]*udpSession)
	c.serverIDs = make(map[uint64]bool)
	c.capacity = n
	c.idle = replayTTL
}
func (c *sessionStore) expire(now time.Time) {
	for len(c.queue) > 0 && !c.queue[0].expires.After(now) {
		s := heap.Pop(&c.queue).(*udpSession)
		delete(c.entries, s.clientID)
		delete(c.serverIDs, s.serverID)
	}
}
func (c *sessionStore) touch(s *udpSession, now time.Time) {
	s.expires = now.Add(c.idle)
	heap.Fix(&c.queue, s.index)
}
