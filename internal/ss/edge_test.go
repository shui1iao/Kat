package ss

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type halfTransport struct {
	memTransport
	half bool
}

func (h *halfTransport) CloseWrite() error { h.half = true; return nil }

type failingTransport struct {
	memTransport
	calls int
}

func (f *failingTransport) Write(b []byte) (int, error) { f.calls++; return 1, io.ErrClosedPipe }
func TestHalfCloseAndFailedWriteAreNotPlaintextFallback(t *testing.T) {
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			wire := tcpRequest(t, s, seq(0x20, s.m.keySize), uint64(testTime.Unix()), testTarget, 1, []byte("still readable"), nil)
			tr := &halfTransport{memTransport: memTransport{input: bytes.NewReader(wire)}}
			c, e := s.Accept(tr)
			if e != nil {
				t.Fatal(e)
			}
			if e = c.CloseWrite(); e != nil || !tr.half || tr.closed {
				t.Fatal(e)
			}
			if _, e = c.Write([]byte("forbidden")); !errors.Is(e, io.ErrClosedPipe) {
				t.Fatal(e)
			}
			p, e := io.ReadAll(c)
			if e != nil || string(p) != "still readable" {
				t.Fatal(string(p), e)
			}
			q := server(t, name)
			f := &failingTransport{memTransport: memTransport{input: bytes.NewReader(wire)}}
			cc, e := q.Accept(f)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = cc.Write([]byte("secret")); !errors.Is(e, io.ErrClosedPipe) {
				t.Fatal(e)
			}
			if _, e = cc.Write([]byte("retry")); !errors.Is(e, io.ErrClosedPipe) || f.calls != 1 {
				t.Fatal("retried poisoned writer", f.calls, e)
			}
		})
	}
}
func TestRecordLengthBoundariesAndTruncation(t *testing.T) {
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			salt := seq(0x20, s.m.keySize)
			a, _ := s.aead(salt)
			limit := MaxChunk2017
			if s.m.v2022 {
				limit = MaxChunk2022
			}
			for _, size := range []int{1, limit - 1, limit} {
				var n counter
				l, _ := seal(a, &n, binary.BigEndian.AppendUint16(nil, uint16(size)))
				data := bytes.Repeat([]byte{7}, size)
				p, _ := seal(a, &n, data)
				r := recordReader{r: bytes.NewReader(append(l, p...)), aead: a, max: limit}
				got, e := io.ReadAll(&r)
				if e != nil || !bytes.Equal(data, got) {
					t.Fatal(size, e)
				}
			}
			if !s.m.v2022 {
				var n counter
				l, _ := seal(a, &n, []byte{0x40, 0})
				r := recordReader{r: bytes.NewReader(l), aead: a, max: limit}
				if _, e := r.Read(make([]byte, 1)); !errors.Is(e, ErrFormat) {
					t.Fatal("2017 upper bits accepted", e)
				}
			}
			var n counter
			l, _ := seal(a, &n, []byte{0, 5})
			p, _ := seal(a, &n, []byte("hello"))
			full := append(l, p...)
			for cut := 1; cut < len(full); cut++ {
				r := recordReader{r: bytes.NewReader(full[:cut]), aead: a, max: limit}
				if _, e := io.ReadAll(&r); e == nil {
					t.Fatal("truncated record accepted", cut)
				}
			}
			// Authenticated zero-length chunks do not invent EOF or lose nonce alignment.
			n = counter{}
			zeroL, _ := seal(a, &n, []byte{0, 0})
			zeroP, _ := seal(a, &n, nil)
			nextL, _ := seal(a, &n, []byte{0, 1})
			nextP, _ := seal(a, &n, []byte("x"))
			stream := append(append(append(zeroL, zeroP...), nextL...), nextP...)
			r := recordReader{r: bytes.NewReader(stream), aead: a, max: limit}
			got, e := io.ReadAll(&r)
			if e != nil || string(got) != "x" {
				t.Fatal(got, e)
			}
		})
	}
}
func modifyTCP2022(t *testing.T, s *Server, wire []byte, fixedChange, variableChange func([]byte)) []byte {
	t.Helper()
	size := s.m.keySize
	a, _ := s.aead(wire[:size])
	var n counter
	f, e := open(a, &n, wire[size:size+27])
	if e != nil {
		t.Fatal(e)
	}
	v, e := open(a, &n, wire[size+27:])
	if e != nil {
		t.Fatal(e)
	}
	if fixedChange != nil {
		fixedChange(f)
	}
	if variableChange != nil {
		variableChange(v)
	}
	n = counter{}
	ff, _ := seal(a, &n, f)
	vv, _ := seal(a, &n, v)
	return append(append(bytes.Clone(wire[:size]), ff...), vv...)
}
func modifyUDP2022(t *testing.T, s *Server, wire []byte, change func([]byte)) []byte {
	t.Helper()
	if s.m.chacha {
		a, _ := chacha20poly1305.NewX(s.key)
		p, e := a.Open(nil, wire[:24], wire[24:], nil)
		if e != nil {
			t.Fatal(e)
		}
		change(p[16:])
		return append(bytes.Clone(wire[:24]), a.Seal(nil, wire[:24], p, nil)...)
	}
	b, _ := aes.NewCipher(s.key)
	h := make([]byte, 16)
	b.Decrypt(h, wire[:16])
	a, _ := s.aead(h[:8])
	p, e := a.Open(nil, h[4:], wire[16:], nil)
	if e != nil {
		t.Fatal(e)
	}
	change(p)
	return append(bytes.Clone(wire[:16]), a.Seal(nil, h[4:], p, nil)...)
}
func TestAuthenticatedMalformedHeadersNeverCommit(t *testing.T) {
	for _, name := range methods[3:] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			base := tcpRequest(t, s, seq(0x20, s.m.keySize), uint64(testTime.Unix()), testTarget, 1, []byte("body"), nil)
			cases := []struct{ f, v func([]byte) }{
				{f: func(b []byte) { b[0] = 1 }},
				{f: func(b []byte) { binary.BigEndian.PutUint64(b[1:9], ^uint64(0)) }},
				{v: func(b []byte) { b[0] = 2 }},
				{v: func(b []byte) { binary.BigEndian.PutUint16(b[7:9], 900) }},
			}
			for i, tc := range cases {
				wire := modifyTCP2022(t, s, base, tc.f, tc.v)
				if _, e := s.Accept(&memTransport{input: bytes.NewReader(wire)}); e == nil {
					t.Fatal("malformed TCP header", i)
				}
				if s.Stats().TCPSalts != 0 {
					t.Fatal("malformed committed salt")
				}
			}
			if _, e := s.Accept(&memTransport{input: bytes.NewReader(base)}); e != nil {
				t.Fatal("invalid attempts changed state", e)
			}
			u := server(t, name)
			original := udpRequest(t, u, 7, 3, uint64(testTime.Unix()), testTarget, []byte("payload"))
			for i, change := range []func([]byte){func(b []byte) { b[0] = 1 }, func(b []byte) { binary.BigEndian.PutUint64(b[1:9], ^uint64(0)) }, func(b []byte) { b[9] = 255; b[10] = 255 }, func(b []byte) { b[11] = 2 }} {
				bad := modifyUDP2022(t, u, original, change)
				if _, e := u.DecodeUDP(bad, testPeer); e == nil {
					t.Fatal("malformed UDP header", i)
				}
				if u.Stats().UDPSessions != 0 {
					t.Fatal("malformed committed session")
				}
			}
			if _, e := u.DecodeUDP(original, testPeer); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestDuplicateRaceAndBoundedHeap(t *testing.T) {
	s := server(t, AES128GCM2022)
	wire := udpRequest(t, s, 10, 1, uint64(testTime.Unix()), testTarget, nil)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.DecodeUDP(wire, testPeer); results <- e }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, ErrReplay) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	for i := 2; i < 100; i++ {
		if _, e := s.DecodeUDP(udpRequest(t, s, 10, uint64(i), uint64(testTime.Unix()), testTarget, nil), testPeer); e != nil {
			t.Fatal(e)
		}
	}
	if len(s.udp.queue) != 1 || len(s.udp.entries) != 1 || len(s.udp.serverIDs) != 1 {
		t.Fatal("refresh leaked heap entries")
	}
	now := testTime
	s.now = func() time.Time { return now }
	now = now.Add(61 * time.Second)
	if st := s.Stats(); st.UDPSessions != 0 || len(s.udp.queue) != 0 || len(s.udp.serverIDs) != 0 {
		t.Fatal("expiration leaked entries", st)
	}
}

// Unix timestamps have second granularity. Retaining state for exactly 60s
// permits a packet timestamped +30s to replay at +60.5s (Unix difference still30).
// 61s retention closes this edge without relaxing the required +/-30s check.
func TestFutureTimestampAtRetentionBoundaryCannotReplay(t *testing.T) {
	for _, name := range methods[3:] {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			now := testTime
			s.now = func() time.Time { return now }
			timestamp := uint64(testTime.Unix() + 30)
			tcp := tcpRequest(t, s, seq(0x20, s.m.keySize), timestamp, testTarget, 1, nil, nil)
			udp := udpRequest(t, s, 33, 1, timestamp, testTarget, nil)
			if _, e := s.Accept(&memTransport{input: bytes.NewReader(tcp)}); e != nil {
				t.Fatal(e)
			}
			if _, e := s.DecodeUDP(udp, testPeer); e != nil {
				t.Fatal(e)
			}
			now = testTime.Add(60500 * time.Millisecond)
			if _, e := s.Accept(&memTransport{input: bytes.NewReader(tcp)}); !errors.Is(e, ErrReplay) {
				t.Fatal("TCP future-time boundary replay", e)
			}
			if _, e := s.DecodeUDP(udp, testPeer); !errors.Is(e, ErrReplay) {
				t.Fatal("UDP future-time boundary replay", e)
			}
			now = testTime.Add(61 * time.Second)
			if _, e := s.Accept(&memTransport{input: bytes.NewReader(tcp)}); !errors.Is(e, ErrTimestamp) {
				t.Fatal(e)
			}
			if _, e := s.DecodeUDP(udp, testPeer); !errors.Is(e, ErrTimestamp) {
				t.Fatal(e)
			}
		})
	}
}
