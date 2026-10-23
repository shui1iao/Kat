package ss

import (
	"hash/maphash"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// Full salt bytes, never a truncated digest: hashing only chooses a chain.
// 32M entries cover >=61s * 2 *259375pps, with no early eviction. On-demand
// chunks avoid a multi-GiB cold allocation. ALL identities share a2GiB raw
// table budget; exhaustion fails closed. Cleanup returns budget only when an
// unreachable chunk is reclaimed, not while any server can still access it.
const default2017Salts = 32 * 1024 * 1024
const compactBudget = int64(2 << 30)
const compactChunkBits = 12
const compactChunkSize = 1 << compactChunkBits
const compactBucketBits = 23
const compactBucketCount = 1 << compactBucketBits

var compactRetained atomic.Int64

type compactEntry struct {
	salt    [32]byte
	expires int64
	next    uint32 // slot+1; zero is end
}
type compactEntries struct {
	data [compactChunkSize]compactEntry
}
type compactBuckets struct{ data [compactChunkSize]uint32 }

func reserveCompact(n int64) bool {
	for {
		old := compactRetained.Load()
		if old+n > compactBudget {
			return false
		}
		if compactRetained.CompareAndSwap(old, old+n) {
			return true
		}
	}
}
func releaseCompact(n int64) { compactRetained.Add(-n) }

type compactSaltStore struct {
	pages           []*compactEntries
	buckets         []*compactBuckets
	seed            maphash.Seed
	capacity, count int
	head, tail      uint32
	keyLen          int
	lastNow         int64
	epoch           time.Time
}

func (c *compactSaltStore) init(n int) { *c = compactSaltStore{capacity: n, seed: maphash.MakeSeed()} }
func (c *compactSaltStore) at(slot uint32) *compactEntry {
	return &c.pages[int(slot)>>compactChunkBits].data[int(slot)&(compactChunkSize-1)]
}
func (c *compactSaltStore) bucket(key []byte) uint32 {
	return uint32(maphash.Bytes(c.seed, key)) & (compactBucketCount - 1)
}
func (c *compactSaltStore) headAt(bucket uint32) *uint32 {
	page := int(bucket) >> compactChunkBits
	if page >= len(c.buckets) || c.buckets[page] == nil {
		return nil
	}
	return &c.buckets[page].data[int(bucket)&(compactChunkSize-1)]
}
func (c *compactSaltStore) expire(now time.Time) {
	ns := now.Sub(c.epoch).Nanoseconds()
	for c.count > 0 {
		e := c.at(c.head)
		if e.expires > ns {
			break
		}
		b := c.headAt(c.bucket(e.salt[:c.keyLen]))
		id := c.head + 1
		for *b != id {
			b = &c.at(*b - 1).next
		}
		*b = e.next
		clear(e.salt[:])
		*e = compactEntry{}
		c.head++
		if int(c.head) == c.capacity {
			c.head = 0
		}
		c.count--
	}
}
func (c *compactSaltStore) admit(salt []byte, now time.Time) error {
	if len(salt) != 16 && len(salt) != 32 {
		return ErrFormat
	}
	if c.keyLen != 0 && len(salt) != c.keyLen {
		return ErrFormat
	}
	c.expire(now)
	var key [32]byte
	copy(key[:], salt)
	bucket := c.bucket(salt)
	head := c.headAt(bucket)
	if head != nil {
		for id := *head; id != 0; id = c.at(id - 1).next {
			if c.at(id-1).salt == key {
				return ErrReplay
			}
		}
	}
	if c.count >= c.capacity {
		return ErrCapacity
	}
	if c.pages == nil {
		c.pages = make([]*compactEntries, (c.capacity+compactChunkSize-1)/compactChunkSize)
		c.buckets = make([]*compactBuckets, compactBucketCount/compactChunkSize)
	}
	bp := int(bucket) >> compactChunkBits
	if c.buckets[bp] == nil {
		size := int64(unsafe.Sizeof(compactBuckets{}))
		if !reserveCompact(size) {
			return ErrCapacity
		}
		p := new(compactBuckets)
		runtime.AddCleanup(p, releaseCompact, size)
		c.buckets[bp] = p
	}
	ep := int(c.tail) >> compactChunkBits
	if c.pages[ep] == nil {
		size := int64(unsafe.Sizeof(compactEntries{}))
		if !reserveCompact(size) {
			return ErrCapacity
		}
		p := new(compactEntries)
		runtime.AddCleanup(p, releaseCompact, size)
		c.pages[ep] = p
	}
	head = c.headAt(bucket)
	e := c.at(c.tail)
	if c.epoch.IsZero() {
		c.epoch = now
	}
	// Epoch/Sub retains Go monotonic time when supplied by time.Now.
	// Clamp backwards test/wall-clock steps rather than expire a later-inserted salt
	// too early; monotone expiry makes the insertion ring an exact expiry queue.
	ns := now.Sub(c.epoch).Nanoseconds()
	if ns < c.lastNow {
		ns = c.lastNow
	}
	c.lastNow = ns
	*e = compactEntry{salt: key, expires: ns + int64(replayTTL), next: *head}
	*head = c.tail + 1
	c.keyLen = len(salt)
	c.tail++
	if int(c.tail) == c.capacity {
		c.tail = 0
	}
	c.count++
	return nil
}
