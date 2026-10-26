package kernel

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"
)

// ---- SOCKS5 UDP fragment reassembly (RFC 1928 section 7) ----
//
// FRAG 1..127 is the position of a fragment, the high bit marks the last
// one. Each association reassembles one datagram at a time. Fragments may
// arrive in any order (UDP reorders); a repeated position with the same
// bytes is ignored, with different bytes (or a different destination) it
// starts a new datagram. The queue is discarded when its timer expires
// (RFC 1928: not less than 5 seconds), when it would exceed the
// association's byte limit or the maximum datagram size, or when the
// process-wide fragment budget is exhausted. Replies are never fragmented.

const (
	defaultFragmentTotal   = 4 << 20 // limits.udp_fragment_bytes
	defaultFragmentAssoc   = 65535   // socks5.udp_fragment.max_bytes
	defaultFragmentTimeout = 5 * time.Second
	maxFragments           = 127
)

// fragmentPool is the process-wide budget of buffered fragment bytes.
type fragmentPool struct {
	used        atomic.Int64
	reassembled atomic.Int64
	dropped     atomic.Int64
}

func (p *fragmentPool) reserve(n, limit int64) bool {
	for {
		old := p.used.Load()
		if old+n > limit {
			return false
		}
		if p.used.CompareAndSwap(old, old+n) {
			return true
		}
	}
}

type reassembly struct {
	pool     *fragmentPool
	limit    func() int64 // process-wide budget (current configuration)
	maxBytes int
	timeout  time.Duration

	mu     sync.Mutex
	parts  *[maxFragments][]byte
	active bool
	closed bool
	target Address
	have   int // fragments held
	end    int // position of the last fragment, 0 = not seen yet
	top    int // highest position held
	size   int // payload bytes held (reserved in pool)
	seq    uint64
	timer  *time.Timer
}

func newReassembly(pool *fragmentPool, limit func() int64, maxBytes int, timeout time.Duration) *reassembly {
	return &reassembly{pool: pool, limit: limit, maxBytes: maxBytes, timeout: timeout}
}

// add takes one fragment (payload is owned by the reassembly from now on).
// It returns the complete datagram when this fragment completes one.
func (r *reassembly) add(frag byte, target Address, payload []byte) (Address, []byte, bool) {
	pos, last := int(frag&0x7f), frag&0x80 != 0
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || pos == 0 {
		r.pool.dropped.Add(1)
		return Address{}, nil, false
	}
	if r.active {
		if target != r.target {
			r.resetLocked(true)
		} else if p := r.parts[pos-1]; p != nil {
			if bytes.Equal(p, payload) {
				r.pool.dropped.Add(1) // duplicate
				return Address{}, nil, false
			}
			r.resetLocked(true)
		} else if (r.end != 0 && pos > r.end) || (last && pos < r.top) {
			r.resetLocked(true) // inconsistent with the datagram being built
		}
	}
	if r.size+len(payload) > r.maxBytes || r.size+len(payload) > maxDatagram {
		r.resetLocked(true)
		r.pool.dropped.Add(1)
		return Address{}, nil, false
	}
	if !r.pool.reserve(int64(len(payload)), r.limit()) {
		r.resetLocked(true)
		r.pool.dropped.Add(1)
		return Address{}, nil, false
	}
	if !r.active {
		if r.parts == nil {
			r.parts = new([maxFragments][]byte)
		}
		r.active, r.target = true, target
		r.seq++
		seq := r.seq
		r.timer = time.AfterFunc(r.timeout, func() { r.expire(seq) })
	}
	// nil marks an absent position. Keep an empty fragment non-nil too,
	// otherwise duplicate empty fragments could increment have twice and
	// complete a datagram while another position is still missing.
	if payload == nil {
		payload = []byte{}
	}
	r.parts[pos-1] = payload
	r.have++
	r.size += len(payload)
	r.top = max(r.top, pos)
	if last {
		r.end = pos
	}
	if r.end == 0 || r.have != r.end {
		return Address{}, nil, false
	}
	out := make([]byte, 0, r.size)
	for i := 0; i < r.end; i++ {
		out = append(out, r.parts[i]...)
	}
	t := r.target
	r.resetLocked(false)
	r.pool.reassembled.Add(1)
	return t, out, true
}

func (r *reassembly) expire(seq uint64) {
	r.mu.Lock()
	if r.active && r.seq == seq {
		r.resetLocked(true)
	}
	r.mu.Unlock()
}

// resetLocked discards the datagram being built; dropped counts its
// fragments as dropped.
func (r *reassembly) resetLocked(dropped bool) {
	if !r.active {
		return
	}
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	if dropped {
		r.pool.dropped.Add(int64(r.have))
	}
	r.pool.used.Add(-int64(r.size))
	clear(r.parts[:])
	r.active, r.have, r.end, r.top, r.size = false, 0, 0, 0, 0
	r.target = Address{}
}

// close discards any partial datagram; later fragments are dropped.
func (r *reassembly) close() {
	r.mu.Lock()
	r.resetLocked(true)
	r.closed = true
	r.parts = nil
	r.mu.Unlock()
}

// newReassembly creates the reassembly of a SOCKS5 association with the
// settings of its inbound; nil when the inbound drops fragments.
func (a *udpAssociation) newReassembly() *reassembly {
	s := a.server
	o := (&Inbound{Protocol: "socks5"}).fragmentOptions()
	if i := inboundOf(a.ctx); i >= 0 && i < len(s.cfg.Inbounds) {
		o = s.cfg.Inbounds[i].fragmentOptions()
	}
	if o == nil {
		return nil
	}
	limit := func() int64 {
		if cur := s.gen.Load(); cur != nil {
			return int64(cur.cfg.Limits.UDPFragmentBytes)
		}
		return defaultFragmentTotal
	}
	return newReassembly(&s.frags, limit, o.MaxBytes, o.Timeout.value())
}
