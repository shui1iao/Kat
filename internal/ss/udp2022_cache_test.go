package ss

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 0.5.19: SS2022 UDP reuses the per-Server header cipher / XChaCha AEAD and the
// per-session request AEAD. Caching must not weaken authentication, replay,
// expiry, or session-creation-only-after-authentication semantics.
func TestUDP2022CachedCiphersKeepAuthReplayAndExpiry(t *testing.T) {
	for _, name := range methods[3:] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			now := testTime
			s.now = func() time.Time { return now }
			req := func(id, pid uint64) []byte {
				return udpRequest(t, s, id, pid, uint64(now.Unix()), testTarget, []byte("cached"))
			}
			// A forged packet for an unknown session creates nothing.
			bad := req(9, 1)
			bad[len(bad)-1] ^= 1
			if _, e := s.DecodeUDP(bad, testPeer); !errors.Is(e, ErrAuth) || len(s.udp.entries) != 0 {
				t.Fatal("forged first packet created state", e)
			}
			p, e := s.DecodeUDP(req(9, 1), testPeer)
			if e != nil || string(p.Payload) != "cached" {
				t.Fatal(e)
			}
			sess := s.udp.entries[9]
			if !s.m.chacha && sess.requestAEAD == nil {
				t.Fatal("request AEAD not retained on authenticated session")
			}
			cached := sess.requestAEAD
			// Tampered packet carrying a live session ID and an unused packet ID:
			// rejected and must not consume that packet ID.
			forged := req(9, 2)
			forged[20] ^= 0x40
			if _, e = s.DecodeUDP(forged, testPeer); !errors.Is(e, ErrAuth) {
				t.Fatal("forged packet on live session accepted", e)
			}
			if _, e = s.DecodeUDP(req(9, 2), testPeer); e != nil {
				t.Fatal("forgery consumed packet ID", e)
			}
			if _, e = s.DecodeUDP(req(9, 2), testPeer); !errors.Is(e, ErrReplay) {
				t.Fatal("replay accepted with cached AEAD", e)
			}
			if s.udp.entries[9].requestAEAD != cached {
				t.Fatal("cached AEAD replaced on later packet")
			}
			// Another server/key cannot reuse anything.
			other, _ := NewServer(Config{Method: name, Key: seq(7, s.m.keySize)})
			other.now = s.now
			if _, e = other.DecodeUDP(req(9, 3), testPeer); !errors.Is(e, ErrAuth) {
				t.Fatal("other key accepted", e)
			}
			// Expiry removes the session; a fresh one still authenticates and reply works.
			now = now.Add(replayTTL + time.Second)
			q, e := s.DecodeUDP(req(9, 1), testPeer)
			if e != nil {
				t.Fatal("new session after expiry", e)
			}
			if _, _, e = s.EncodeUDP(q, testTarget, []byte("r")); e != nil {
				t.Fatal(e)
			}
			if _, _, e = s.EncodeUDP(p, testTarget, []byte("r")); !errors.Is(e, ErrSessionExpired) {
				t.Fatal("expired session capability replied", e)
			}
		})
	}
}

func TestUDP2022CachedConcurrentExactlyOnce(t *testing.T) {
	for _, name := range methods[3:] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			const ids, per = 4, 64
			var wires [ids][per][]byte
			for id := range ids {
				for pid := range per {
					wires[id][pid] = udpRequest(t, s, uint64(100+id), uint64(pid), uint64(testTime.Unix()), testTarget, []byte{byte(pid)})
				}
			}
			var ok, replay atomic.Int64
			var wg sync.WaitGroup
			for w := range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for id := range ids {
						for pid := range per {
							p, e := s.DecodeUDP(wires[id][(pid+w)%per], testPeer)
							switch {
							case e == nil:
								ok.Add(1)
								if _, _, e = s.EncodeUDP(p, testTarget, p.Payload); e != nil {
									t.Error(e)
								}
							case errors.Is(e, ErrReplay):
								replay.Add(1)
							default:
								t.Error(e)
							}
						}
					}
				}()
			}
			wg.Wait()
			if ok.Load() != ids*per || replay.Load() != 7*ids*per {
				t.Fatalf("accepted %d replay %d", ok.Load(), replay.Load())
			}
		})
	}
}

func BenchmarkUDP2022DecodeLiveSession(b *testing.B) {
	m, _ := lookup(AES128GCM2022)
	s, _ := NewServer(Config{Method: AES128GCM2022, Key: seq(0, m.keySize)})
	s.now = func() time.Time { return testTime }
	t := &testing.T{}
	wires := make([][]byte, b.N+1)
	for i := range wires {
		wires[i] = udpRequest(t, s, 1, uint64(i), uint64(testTime.Unix()), testTarget, make([]byte, 1200))
	}
	if _, e := s.DecodeUDP(wires[0], testPeer); e != nil {
		b.Fatal(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		if _, e := s.DecodeUDP(wires[i], testPeer); e != nil {
			b.Fatal(e)
		}
	}
}
