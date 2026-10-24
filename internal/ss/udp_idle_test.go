package ss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func idleServer(t *testing.T, name string, idle time.Duration) (*Server, *atomic.Int64) {
	t.Helper()
	m, e := lookup(name)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewServer(Config{Method: name, Key: seq(0, m.keySize), UDPIdle: idle, MaxUDPSessions: 2})
	if e != nil {
		t.Fatal(e)
	}
	clock := new(atomic.Int64)
	clock.Store(testTime.UnixNano())
	s.now = func() time.Time { return time.Unix(0, clock.Load()) }
	return s, clock
}
func idleResponseStamp(t *testing.T, s *Server, w []byte) uint64 {
	t.Helper()
	var p []byte
	if s.m.chacha {
		a, _ := chacha20poly1305.NewX(s.key)
		all, e := a.Open(nil, w[:24], w[24:], nil)
		if e != nil {
			t.Fatal(e)
		}
		p = all[16:]
	} else {
		h := make([]byte, 16)
		s.udpHeader.Decrypt(h, w[:16])
		a, e := s.aead(h[:8])
		if e != nil {
			t.Fatal(e)
		}
		p, e = a.Open(nil, h[4:], w[16:], nil)
		if e != nil {
			t.Fatal(e)
		}
	}
	return binary.BigEndian.Uint64(p[1:9])
}

func TestUDPIdleConfiguredBidirectionalAndSecurity(t *testing.T) {
	for _, name := range methods[3:] {
		t.Run(name, func(t *testing.T) {
			s, clock := idleServer(t, name, 5*time.Minute)
			now := func() time.Time { return time.Unix(0, clock.Load()) }
			advance := func(d time.Duration) { clock.Add(int64(d)) }
			req := func(id, pid uint64, at time.Time) []byte {
				return udpRequest(t, s, id, pid, uint64(at.Unix()), testTarget, []byte("request"))
			}
			oldwire := req(10, 1, now())
			p, e := s.DecodeUDP(oldwire, testPeer)
			if e != nil {
				t.Fatal(e)
			}
			sess := p.session
			sid := sess.serverID
			advance(70 * time.Second) // decisive regression: previous 61s codec expired here.
			w, peer, e := s.EncodeUDP(p, testTarget, []byte("late but within idle"))
			if e != nil || peer != testPeer {
				t.Fatal("reply beyond 61s failed", e, peer)
			}
			if stamp := idleResponseStamp(t, s, w); stamp != uint64(now().Unix()) {
				t.Fatal("response reused old packet timestamp", stamp)
			}
			if p.session != sess || sess.serverID != sid || sess.nextPacket != 1 {
				t.Fatal("response recreated session/counter")
			}
			advance(290 * time.Second) // t=360s: outgoing reply must renew the configured idle.
			if _, _, e = s.EncodeUDP(p, testTarget, nil); e != nil {
				t.Fatal("valid reply did not renew idle", e)
			}
			before := sess.expires
			win := sess.window
			previousPeer := sess.peer
			bad := req(10, 4000, now())
			bad[len(bad)-1] ^= 1
			evil := netip.MustParseAddrPort("127.0.0.1:54321")
			if _, e = s.DecodeUDP(bad, evil); !errors.Is(e, ErrAuth) {
				t.Fatal(e)
			}
			if _, e = s.DecodeUDP(req(10, 4000, now().Add(-31*time.Second)), evil); !errors.Is(e, ErrTimestamp) {
				t.Fatal("timestamp relaxed", e)
			}
			if _, e = s.DecodeUDP(req(10, 4000, now().Add(31*time.Second)), evil); !errors.Is(e, ErrTimestamp) {
				t.Fatal("future timestamp relaxed", e)
			}
			if _, e = s.DecodeUDP(oldwire, evil); !errors.Is(e, ErrTimestamp) {
				t.Fatal("expired packet admitted into retained state", e)
			}
			if sess.expires != before || sess.window != win || sess.peer != previousPeer {
				t.Fatal("invalid packet renewed/migrated/consumed state")
			}
			// A current timestamp cannot bypass duplicate or packet-window checks.
			if _, e = s.DecodeUDP(req(10, 1, now()), evil); !errors.Is(e, ErrReplay) {
				t.Fatal("replay accepted", e)
			}
			q, e := s.DecodeUDP(req(10, 4000, now()), evil)
			if e != nil {
				t.Fatal("forgery consumed ID", e)
			}
			if q.session != sess || q.AuthenticatedAt() != now() {
				t.Fatal("legitimate activity changed identity/clock")
			}
			if _, e = s.DecodeUDP(req(10, 2976, now()), testPeer); !errors.Is(e, ErrReplay) {
				t.Fatal("outside window accepted", e)
			}
			if _, peer, e = s.EncodeUDP(p, testTarget, nil); e != nil || peer != evil {
				t.Fatal("old capability did not follow authenticated migration", e, peer)
			}
			// Valid incoming traffic also renews while preserving response counter/server ID.
			advance(290 * time.Second)
			if _, e = s.DecodeUDP(req(10, 4001, now()), testPeer); e != nil {
				t.Fatal(e)
			}
			if sess.serverID != sid || sess.nextPacket != 3 {
				t.Fatal("nonce/session state reset on activity")
			}
			expiry := sess.expires
			advance(300 * time.Second)
			if !now().Equal(expiry) {
				t.Fatal("unexpected expiry", now(), expiry)
			}
			if _, _, e = s.EncodeUDP(p, testTarget, nil); !errors.Is(e, ErrSessionExpired) {
				t.Fatal("idle capability survived", e)
			}
			if len(s.udp.entries) != 0 || len(s.udp.serverIDs) != 0 || len(s.udp.queue) != 0 {
				t.Fatal("expired session state retained")
			}
			if _, e = s.DecodeUDP(oldwire, evil); !errors.Is(e, ErrTimestamp) {
				t.Fatal("expired replay recreated session", e)
			}
			fresh, e := s.DecodeUDP(req(10, 0, now()), evil)
			if e != nil || fresh.session == sess {
				t.Fatal("fresh authentication after idle", e)
			}
			if _, _, e = s.EncodeUDP(p, testTarget, nil); !errors.Is(e, ErrSessionExpired) {
				t.Fatal("old capability attached to recreated session", e)
			}
			if fresh.session.peer != evil {
				t.Fatal("fresh peer not committed")
			}
		})
	}
}

func TestUDPIdleRetentionDoesNotAlterSaltTTLOrCapacity(t *testing.T) {
	s, clock := idleServer(t, AES128GCM2022, 5*time.Minute)
	if e := s.tcpSalts.admit([]byte("fixed-tcp-salt"), testTime); e != nil {
		t.Fatal(e)
	}
	now := testTime.Add(62 * time.Second)
	clock.Store(now.UnixNano())
	s.tcpSalts.expire(now)
	if len(s.tcpSalts.entries) != 0 {
		t.Fatal("UDP idle polluted TCP salt TTL")
	}
	q, _ := NewServer(Config{Method: AES128GCM, Key: seq(0, 16), UDPIdle: 5 * time.Minute, Max2017Salts: 8})
	q.now = s.now
	if e := q.oldSalts.admit(seq(20, 16), now); e != nil {
		t.Fatal(e)
	}
	q.oldSalts.expire(now.Add(62 * time.Second))
	if q.oldSalts.count != 0 {
		t.Fatal("SS2017 salt retention changed")
	}
	s.udp.capacity = 1
	p, e := s.DecodeUDP(udpRequest(t, s, 1, 1, uint64(now.Unix()), testTarget, nil), testPeer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DecodeUDP(udpRequest(t, s, 2, 1, uint64(now.Unix()), testTarget, nil), testPeer); !errors.Is(e, ErrCapacity) {
		t.Fatal("capacity bypass", e)
	}
	before := p.session.expires
	bad := udpRequest(t, s, 2, 2, uint64(now.Unix()), testTarget, nil)
	bad[len(bad)-1] ^= 1
	if _, e = s.DecodeUDP(bad, testPeer); !errors.Is(e, ErrAuth) || p.session.expires != before {
		t.Fatal("bad auth affected full cache", e)
	}
	if _, e := NewServer(Config{Method: AES128GCM2022, Key: seq(0, 16), UDPIdle: -time.Second}); e == nil {
		t.Fatal("negative idle")
	}
	if _, e := NewServer(Config{Method: AES128GCM2022, Key: seq(0, 16), UDPIdle: 25 * time.Hour}); e == nil {
		t.Fatal("unbounded idle")
	}
	short, _ := idleServer(t, AES128GCM2022, time.Millisecond)
	if short.udp.idle != replayTTL {
		t.Fatal("short association lost replay retention floor")
	}
}

func TestUDPIdleConcurrentRetainedSession(t *testing.T) {
	s, clock := idleServer(t, AES128GCM2022, 5*time.Minute)
	p, e := s.DecodeUDP(udpRequest(t, s, 9, 1, uint64(testTime.Unix()), testTarget, nil), testPeer)
	if e != nil {
		t.Fatal(e)
	}
	clock.Store(testTime.Add(70 * time.Second).UnixNano())
	var wg sync.WaitGroup
	var fresh, replayed atomic.Int64
	wire := udpRequest(t, s, 9, 2, uint64(s.now().Unix()), testTarget, []byte("fresh"))
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				_, e := s.DecodeUDP(bytes.Clone(wire), testPeer)
				if e == nil {
					fresh.Add(1)
				} else if errors.Is(e, ErrReplay) {
					replayed.Add(1)
				} else {
					t.Error(e)
				}
				if _, _, e = s.EncodeUDP(p, testTarget, []byte("response")); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	if fresh.Load() != 1 || replayed.Load() != 63 || p.session.nextPacket != 64 {
		t.Fatal("concurrent replay/nonce accounting", fresh.Load(), replayed.Load(), p.session.nextPacket)
	}
}
