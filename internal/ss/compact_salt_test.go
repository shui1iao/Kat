package ss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func compactKey(n uint64, size int) []byte {
	p := make([]byte, size)
	binary.LittleEndian.PutUint64(p, n)
	return p
}
func TestCompactExactExpiryCapacity(t *testing.T) {
	for _, size := range []int{16, 32} {
		var c compactSaltStore
		c.init(17)
		for cycle := 0; cycle < 3; cycle++ {
			now := testTime.Add(time.Duration(cycle) * 61 * time.Second)
			for i := 0; i < 17; i++ {
				if e := c.admit(compactKey(uint64(i), size), now); e != nil {
					t.Fatal(e)
				}
			}
			if e := c.admit(compactKey(1, size), now); e != ErrReplay {
				t.Fatal(e)
			}
			if e := c.admit(compactKey(99, size), now); e != ErrCapacity {
				t.Fatal(e)
			}
			c.expire(now.Add(61*time.Second - time.Nanosecond))
			if c.count != 17 {
				t.Fatal("early expiry")
			}
			c.expire(now.Add(61 * time.Second))
			if c.count != 0 {
				t.Fatal("late expiry")
			}
			for _, p := range c.pages {
				if p != nil {
					for _, e := range p.data {
						if e != (compactEntry{}) {
							t.Fatal("expired slot not cleared")
						}
					}
				}
			}
		}
	}
}
func TestCompactHashCollisionFullKey(t *testing.T) {
	var c compactSaltStore
	c.init(3)
	a := compactKey(1, 16)
	bucket := c.bucket(a)
	var b []byte
	for n := uint64(2); ; n++ {
		k := compactKey(n, 16)
		if c.bucket(k) == bucket {
			b = k
			break
		}
	}
	if e := c.admit(a, testTime); e != nil {
		t.Fatal(e)
	}
	if e := c.admit(b, testTime); e != nil {
		t.Fatal("hash collision falsely rejected", e)
	}
	if e := c.admit(a, testTime); e != ErrReplay {
		t.Fatal(e)
	}
	if e := c.admit(b, testTime); e != ErrReplay {
		t.Fatal(e)
	}
	c.expire(testTime.Add(61 * time.Second))
	if c.count != 0 {
		t.Fatal("chain deletion")
	}
}
func TestCompact2017BeyondOldBudgetAndReflection(t *testing.T) {
	for _, name := range methods[:3] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			addr, _ := testTarget.MarshalBinary()
			body := append(addr, []byte("payload")...)
			makewire := func(id uint64) []byte {
				salt := compactKey(id, s.m.keySize)
				a, _ := s.aead(salt)
				return append(salt, a.Seal(nil, make([]byte, 12), body, nil)...)
			}
			var first, response []byte
			for i := uint64(1); i <= 40000; i++ {
				wire := makewire(i)
				p, e := s.DecodeUDP(wire, testPeer)
				if e != nil {
					t.Fatal(i, e)
				}
				out, _, e := s.EncodeUDP(p, testTarget, p.Payload)
				if e != nil {
					t.Fatal(i, e)
				}
				if i == 1 {
					first = wire
					response = out
				}
			}
			if s.Stats().Salts2017 != 80000 {
				t.Fatal(s.Stats())
			}
			if _, e := s.DecodeUDP(first, testPeer); !errors.Is(e, ErrReplay) {
				t.Fatal("request replay", e)
			}
			if _, e := s.DecodeUDP(response, testPeer); !errors.Is(e, ErrReplay) {
				t.Fatal("response reflection", e)
			}
			s.random = bytes.NewReader(bytes.Repeat(response[:s.m.keySize], 8))
			if _, e := s.responseSalt(); !errors.Is(e, ErrReplay) {
				t.Fatal("outgoing collision", e)
			}
		})
	}
}
func TestCompactSerializedConcurrentAdmission(t *testing.T) {
	s := server(t, AES128GCM)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				k := compactKey(uint64(g*100+i), 16)
				s.mu.Lock()
				e := s.oldSalts.admit(k, testTime)
				again := s.oldSalts.admit(k, testTime)
				s.mu.Unlock()
				if e != nil || again != ErrReplay {
					t.Errorf("%v %v", e, again)
				}
			}
		}(g)
	}
	wg.Wait()
	if s.Stats().Salts2017 != 800 {
		t.Fatal(s.Stats())
	}
}
func TestCompactGlobalBudgetFailsClosed(t *testing.T) {
	// Basic oversized request guard; real nonzero-store allocation failures and
	// cleanup accounting are covered in TestCompactGlobalBudgetAllocationPaths.
	if reserveCompact(compactBudget + 1) {
		releaseCompact(compactBudget + 1)
		t.Fatal("global budget exceeded")
	}
	if compactRetained.Load() > compactBudget {
		t.Fatal("raw allocations exceed bound")
	}
	var c compactSaltStore
	c.init(0)
	if e := c.admit(compactKey(1, 16), testTime); e != ErrCapacity {
		t.Fatal(e)
	}
	if c.count != 0 {
		t.Fatal("failed allocation committed salt")
	}
}
func BenchmarkCompactFullBudget(b *testing.B) {
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var c compactSaltStore
		c.init(default2017Salts)
		var key [16]byte
		for n := uint64(0); n < default2017Salts; n++ {
			binary.LittleEndian.PutUint64(key[:], n)
			if e := c.admit(key[:], testTime); e != nil {
				b.Fatal(n, e)
			}
		}
		if c.admit(compactKey(default2017Salts, 16), testTime) != ErrCapacity {
			b.Fatal("full table did not close")
		}
		runtime.ReadMemStats(&after)
		b.Logf("entries=%d entrySize=%d rawGlobal=%d heapDelta=%d coldAllocIsLazy=true", c.count, unsafe.Sizeof(compactEntry{}), compactRetained.Load(), after.HeapAlloc-before.HeapAlloc)
		runtime.KeepAlive(c)
	}
}

func TestCompactEpochAndBackwardsClock(t *testing.T) {
	var c compactSaltStore
	c.init(3)
	now := time.Now()
	if e := c.admit(compactKey(1, 16), now); e != nil {
		t.Fatal(e)
	}
	if c.epoch != now || c.at(0).expires != int64(replayTTL) {
		t.Fatal("epoch/relative expiration")
	}
	if e := c.admit(compactKey(2, 16), now.Add(-time.Second)); e != nil {
		t.Fatal(e)
	}
	c.expire(now.Add(replayTTL - time.Nanosecond))
	if c.count != 2 {
		t.Fatal("early expiry with clock step")
	}
	c.expire(now.Add(replayTTL))
	if c.count != 0 {
		t.Fatal("relative deadline expiry")
	}
}
