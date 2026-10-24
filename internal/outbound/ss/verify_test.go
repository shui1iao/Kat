package ss

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func testOutbound(t *testing.T, method string) *Outbound {
	t.Helper()
	m, ok := lookup(method)
	if !ok {
		t.Fatal(method)
	}
	key := make([]byte, m.keySize)
	rand.Read(key)
	s := &Outbound{name: "t", m: m, key: key, server: outbound.Addr{Host: "127.0.0.1", Port: 1}, now: time.Now}
	var e error
	if m.chacha {
		s.udpX, e = newXChaCha(key)
	} else {
		s.udpBlock, e = newAESBlock(key)
	}
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// SIP022 TCP response checks: request-salt echo and timestamp window.
func TestTCP2022ResponseVerification(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"} {
		for _, tc := range []struct {
			name    string
			skew    time.Duration
			badSalt bool
			want    error
		}{{"ok", 0, false, nil}, {"stale", -40 * time.Second, false, errTime}, {"future", 40 * time.Second, false, errTime}, {"salt", 0, true, errSalt}} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				s := testOutbound(t, method)
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				c := &tcpConn{Conn: client, s: s, addr: []byte{1, 127, 0, 0, 1, 0, 80}, sentCh: make(chan struct{})}
				go func() {
					req := make([]byte, s.m.keySize)
					if _, e := io.ReadFull(server, req); e != nil {
						return
					}
					go io.Copy(io.Discard, server)
					if tc.badSalt {
						req[0] ^= 1
					}
					salt := make([]byte, s.m.keySize)
					rand.Read(salt)
					a, _ := sessionAEAD(s.m, s.key, salt)
					var n nonce
					h := []byte{1}
					h = binary.BigEndian.AppendUint64(h, uint64(time.Now().Add(tc.skew).Unix()))
					h = append(h, req...)
					h = binary.BigEndian.AppendUint16(h, 5)
					_, n0 := n.next()
					w := a.Seal(salt, n0, h, nil)
					_, n1 := n.next()
					w = a.Seal(w, n1, []byte("hello"), nil)
					server.Write(w)
				}()
				if _, e := c.Write([]byte("ping")); e != nil {
					t.Fatal(e)
				}
				client.SetReadDeadline(time.Now().Add(2 * time.Second))
				b := make([]byte, 16)
				k, e := c.Read(b)
				if tc.want == nil {
					if e != nil || string(b[:k]) != "hello" {
						t.Fatalf("%q %v", b[:k], e)
					}
				} else if !errors.Is(e, tc.want) {
					t.Fatalf("got %v want %v", e, tc.want)
				}
			})
		}
	}
}

// encodeResponse is a test-only SIP022 server-to-client UDP encoder.
func encodeResponse(s *Outbound, serverID, packetID, clientID uint64, stamp time.Time, payload []byte) []byte {
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], serverID)
	binary.BigEndian.PutUint64(header[8:], packetID)
	body := []byte{1}
	body = binary.BigEndian.AppendUint64(body, uint64(stamp.Unix()))
	body = binary.BigEndian.AppendUint64(body, clientID)
	body = append(body, 0, 3, 9, 9, 9) // 3 bytes padding
	body = append(body, 1, 127, 0, 0, 1, 0, 53)
	body = append(body, payload...)
	if s.m.chacha {
		n := make([]byte, 24)
		rand.Read(n)
		return s.udpX.Seal(n, n, append(header[:], body...), nil)
	}
	a, _ := sessionAEAD(s.m, s.key, header[:8])
	w := make([]byte, 16)
	s.udpBlock.Encrypt(w, header[:])
	return a.Seal(w, header[4:16], body, nil)
}

// SIP022 UDP response checks: client session binding, timestamp window,
// per-server-session replay window, server session change.
func TestUDP2022ResponseVerification(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			s := testOutbound(t, method)
			p := &udpConn{s: s, session: 77}
			now := time.Now()
			check := func(name string, wire []byte, ok bool) {
				t.Helper()
				src, payload, e := p.decode2022(wire)
				if ok != (e == nil) {
					t.Fatalf("%s: err=%v", name, e)
				}
				if ok && (string(payload) != "pong" || src.Host != "127.0.0.1" || src.Port != 53) {
					t.Fatalf("%s: %q %v", name, payload, src)
				}
			}
			check("valid", encodeResponse(s, 1000, 0, 77, now, []byte("pong")), true)
			check("replay", encodeResponse(s, 1000, 0, 77, now, []byte("pong")), false)
			check("next", encodeResponse(s, 1000, 1, 77, now, []byte("pong")), true)
			check("foreign client session", encodeResponse(s, 1000, 2, 78, now, []byte("pong")), false)
			check("stale timestamp", encodeResponse(s, 1000, 3, 77, now.Add(-31*time.Second), []byte("pong")), false)
			check("future timestamp", encodeResponse(s, 1000, 4, 77, now.Add(31*time.Second), []byte("pong")), false)
			wire := encodeResponse(s, 1000, 5, 77, now, []byte("pong"))
			wire[len(wire)-1] ^= 1
			check("tampered", wire, false)
			check("new server session", encodeResponse(s, 2000, 0, 77, now, []byte("pong")), true)
			check("old session still tracked", encodeResponse(s, 1000, 6, 77, now, []byte("pong")), true)
			check("old session replay", encodeResponse(s, 1000, 1, 77, now, []byte("pong")), false)
			other := testOutbound(t, method)
			check("wrong key", encodeResponse(other, 1000, 7, 77, now, []byte("pong")), false)
		})
	}
}
