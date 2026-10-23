package ss

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// 0.5.20: SS2022 responses are sealed outside the codec lock. Concurrent
// replies on one session must still use unique, never-reused packet IDs, stay
// bound to the session/latest peer, and decrypt to the exact body.
func TestUDP2022EncodeOutsideLockUniqueCounterAndBody(t *testing.T) {
	for _, name := range methods[3:] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			p, e := s.DecodeUDP(udpRequest(t, s, 77, 1, uint64(testTime.Unix()), testTarget, []byte("q")), testPeer)
			if e != nil {
				t.Fatal(e)
			}
			sess := s.udp.entries[77]
			const workers, per = 8, 64
			wires := make(chan []byte, workers*per)
			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range per {
						w, peer, e := s.EncodeUDP(p, testTarget, []byte("reply-body"))
						if e != nil || peer != testPeer {
							t.Error(e, peer)
							return
						}
						wires <- w
					}
				}()
			}
			wg.Wait()
			close(wires)
			seen := map[uint64]bool{}
			var sid [8]byte
			binary.BigEndian.PutUint64(sid[:], sess.serverID)
			resp, _ := s.aead(sid[:])
			for w := range wires {
				var header, plain []byte
				if s.m.chacha {
					x, _ := chacha20poly1305.NewX(s.key)
					all, e := x.Open(nil, w[:24], w[24:], nil)
					if e != nil {
						t.Fatal(e)
					}
					header, plain = all[:16], all[16:]
				} else {
					header = make([]byte, 16)
					s.udpHeader.Decrypt(header, w[:16])
					var e error
					if plain, e = resp.Open(nil, header[4:16], w[16:], nil); e != nil {
						t.Fatal(e)
					}
				}
				if binary.BigEndian.Uint64(header[:8]) != sess.serverID {
					t.Fatal("wrong server session ID")
				}
				id := binary.BigEndian.Uint64(header[8:])
				if seen[id] {
					t.Fatal("response packet ID reused", id)
				}
				seen[id] = true
				if plain[0] != 1 || binary.BigEndian.Uint64(plain[1:9]) != uint64(testTime.Unix()) || binary.BigEndian.Uint64(plain[9:17]) != 77 || plain[17] != 0 || plain[18] != 0 || !bytes.HasSuffix(plain, []byte("reply-body")) {
					t.Fatal("response body mismatch")
				}
			}
			if len(seen) != workers*per || sess.nextPacket != workers*per {
				t.Fatalf("ids %d next %d", len(seen), sess.nextPacket)
			}
			// Expiry still fails closed for an old capability.
			now := testTime.Add(replayTTL + time.Second)
			s.now = func() time.Time { return now }
			if _, _, e = s.EncodeUDP(p, testTarget, nil); e != ErrSessionExpired {
				t.Fatal("expired session encoded", e)
			}
		})
	}
}

func BenchmarkUDP2022Encode(b *testing.B) {
	m, _ := lookup(AES128GCM2022)
	s, _ := NewServer(Config{Method: AES128GCM2022, Key: seq(0, m.keySize)})
	s.now = func() time.Time { return testTime }
	p, e := s.DecodeUDP(udpRequest(&testing.T{}, s, 1, 1, uint64(testTime.Unix()), testTarget, nil), testPeer)
	if e != nil {
		b.Fatal(e)
	}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, e := s.EncodeUDP(p, testTarget, payload); e != nil {
			b.Fatal(e)
		}
	}
}
