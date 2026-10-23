package snell

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPSK = "snell-stage-fixture-psk"

type memConn struct {
	*bytes.Reader
	out    bytes.Buffer
	closed bool
}

func (m *memConn) Write(p []byte) (int, error) { return m.out.Write(p) }
func (m *memConn) Close() error                { m.closed = true; return nil }
func wireFile(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + ".hex")
	if e != nil {
		t.Fatal(e)
	}
	b, e = hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func newSrv(t *testing.T, c Config) *Server {
	t.Helper()
	if len(c.PSK) == 0 {
		c.PSK = []byte(testPSK)
	}
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func captureAccept(t *testing.T, s *Server, b []byte) (*Session, *memConn) {
	t.Helper()
	m := &memConn{Reader: bytes.NewReader(b)}
	x, e := s.Accept(m)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { x.Close() })
	return x, m
}
func mustTest(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func TestFixedIndependentFixture(t *testing.T) {
	s, m := captureAccept(t, newSrv(t, Config{}), wireFile(t, "peer-connect"))
	q, e := s.Next()
	mustTest(t, e)
	if q.Target != (Address{"example.org", 443}) || q.Command != 5 {
		t.Fatal(q.Target)
	}
	got, e := io.ReadAll(q)
	mustTest(t, e)
	want := append([]byte("fixture early data"), bytes.Repeat([]byte("0123456789"), 3000)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture payload mismatch %d", len(got))
	}
	mustTest(t, q.Approve())
	_, e = q.Write([]byte("server-first"))
	mustTest(t, e)
	mustTest(t, q.Finish())
	r := responseReader(t, m.out.Bytes())
	b, e := r.next()
	mustTest(t, e)
	if !bytes.Equal(b, []byte("\x00server-first")) {
		t.Fatalf("response %q", b)
	}
	if _, e = r.next(); e != io.EOF {
		t.Fatalf("zero EOF %v", e)
	}
}
func responseReader(t *testing.T, b []byte) *recordReader {
	t.Helper()
	if len(b) < 16 {
		t.Fatal("no salt")
	}
	a, e := aeadFor([]byte(testPSK), b[:16])
	mustTest(t, e)
	return &recordReader{src: bytes.NewReader(b[16:]), a: a}
}
func TestFixedNegativeVectors(t *testing.T) {
	for _, name := range []string{"zero-padding", "oversize-payload", "oversize-padding", "reserved", "bad-version"} {
		t.Run(name, func(t *testing.T) {
			m := &memConn{Reader: bytes.NewReader(wireFile(t, name))}
			s := newSrv(t, Config{})
			if _, e := s.Accept(m); e == nil {
				t.Fatal("accepted")
			}
			if !m.closed || len(s.slots) != 0 {
				t.Fatal("not reclaimed")
			}
		})
	}
	k := []byte{0x6b, 0x06, 0x80, 0x16, 0xd9, 0x6d, 0x1e, 0x75, 0x77, 0xb2, 0xd1, 0xae, 0x27, 0x8b, 0x47, 0x14}
	a, e := aeadFor([]byte(testPSK), bytes.Repeat([]byte{0x42}, 16))
	mustTest(t, e)
	b, e := aes.NewCipher(k)
	mustTest(t, e)
	other, e := cipher.NewGCM(b)
	mustTest(t, e)
	if !bytes.Equal(a.Seal(nil, make([]byte, 12), []byte("KDF known answer"), nil), other.Seal(nil, make([]byte, 12), []byte("KDF known answer"), nil)) {
		t.Fatal("peer KDF vector mismatch")
	}
}
func TestTagTruncationReplayAndCapacity(t *testing.T) {
	wire := wireFile(t, "peer-connect")
	for _, i := range []int{16, 38, 39} {
		b := bytes.Clone(wire)
		b[i] ^= 0x40
		m := &memConn{Reader: bytes.NewReader(b)}
		if _, e := newSrv(t, Config{}).Accept(m); e == nil {
			t.Fatalf("bad tag accepted %d", i)
		}
	}
	for _, n := range []int{0, 1, 15, 16, 20, 38, 39, 100} {
		m := &memConn{Reader: bytes.NewReader(wire[:n])}
		if _, e := newSrv(t, Config{}).Accept(m); e == nil {
			t.Fatalf("truncated accepted %d", n)
		}
	}
	s := newSrv(t, Config{ReplayCapacity: 1})
	x, _ := captureAccept(t, s, wire)
	x.Close()
	if _, e := s.Accept(&memConn{Reader: bytes.NewReader(wire)}); !errors.Is(e, ErrReplay) {
		t.Fatal(e)
	}
	var w bytes.Buffer
	rw := recordWriter{dst: &w, psk: []byte(testPSK)}
	_, e := rw.stream([]byte{1, 6, 0})
	mustTest(t, e)
	if _, e = s.Accept(&memConn{Reader: bytes.NewReader(w.Bytes())}); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	s.replayMu.Lock()
	s.ring[s.head].expires = time.Now().Add(-time.Second)
	s.replayMu.Unlock()
	x, e = s.Accept(&memConn{Reader: bytes.NewReader(w.Bytes())})
	mustTest(t, e)
	x.Close()
}
func requestBytes(cmd byte, a Address, early []byte) []byte {
	b := []byte{1, cmd, 0}
	if cmd == 1 || cmd == 5 {
		b = append(b, byte(len(a.Host)))
		b = append(b, a.Host...)
		b = append(b, byte(a.Port>>8), byte(a.Port))
	}
	return append(b, early...)
}
func TestRequestsAndAuthenticatedErrors(t *testing.T) {
	for _, b := range [][]byte{{2, 5, 0}, {1, 99, 0}, {1, 5, 2, 1}, {1, 5, 0, 0, 0, 80}, {1, 5, 0, 3, 'a', ' ', 'b', 0, 80}, {1, 5, 0, 1, 'x', 0, 0}, {1, 6, 0, 99}} {
		var wire bytes.Buffer
		w := recordWriter{dst: &wire, psk: []byte(testPSK)}
		mustTest(t, w.packet(b))
		x, m := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
		if _, e := x.Next(); e == nil {
			t.Fatalf("accepted %x", b)
		}
		r := responseReader(t, m.out.Bytes())
		p, e := r.next()
		mustTest(t, e)
		if p[0] != 2 || !m.closed {
			t.Fatal("missing error/close")
		}
	}
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet([]byte{1, 0, 255}))
	x, m := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
	if _, e := x.Next(); e != io.EOF {
		t.Fatal(e)
	}
	r := responseReader(t, m.out.Bytes())
	p, e := r.next()
	mustTest(t, e)
	if !bytes.Equal(p, []byte{1}) {
		t.Fatal(p)
	}
}
func TestSequentialReuseDrainAndStaleRequest(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"one.example", 80}, []byte("old early"))))
	mustTest(t, w.packet([]byte("old tail must be discarded")))
	mustTest(t, w.end())
	mustTest(t, w.packet(requestBytes(5, Address{"::1", 443}, []byte("new"))))
	mustTest(t, w.end())
	x, m := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
	q, e := x.Next()
	mustTest(t, e)
	if _, e = x.Next(); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	if _, e = q.Write([]byte("forbidden")); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	mustTest(t, q.Approve())
	_, e = q.Write([]byte("first"))
	mustTest(t, e)
	mustTest(t, q.Finish())
	if _, e = q.Read(make([]byte, 1)); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	q2, e := x.Next()
	mustTest(t, e)
	if q2.Target.Host != "::1" {
		t.Fatal(q2.Target)
	}
	b, e := io.ReadAll(q2)
	mustTest(t, e)
	if string(b) != "new" {
		t.Fatalf("tail leak %q", b)
	}
	mustTest(t, q2.Approve())
	_, e = q2.Write([]byte("second"))
	mustTest(t, e)
	mustTest(t, q2.Finish())
	r := responseReader(t, m.out.Bytes())
	for _, expected := range []string{"\x00first", "", "\x00second", ""} {
		b, e := r.next()
		if expected == "" {
			if e != io.EOF {
				t.Fatal(e)
			}
		} else {
			mustTest(t, e)
			if string(b) != expected {
				t.Fatal(string(b))
			}
		}
	}
}
func TestDrainAndRequestLimits(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"x", 1}, []byte("large tail"))))
	mustTest(t, w.end())
	x, _ := captureAccept(t, newSrv(t, Config{DrainLimit: 1}), wire.Bytes())
	q, e := x.Next()
	mustTest(t, e)
	mustTest(t, q.Approve())
	mustTest(t, q.SendSuccess())
	if e = q.Finish(); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	var w2 bytes.Buffer
	rw := recordWriter{dst: &w2, psk: []byte(testPSK)}
	for i := 0; i < 2; i++ {
		mustTest(t, rw.packet(requestBytes(5, Address{"x", 1}, nil)))
		mustTest(t, rw.end())
	}
	x, _ = captureAccept(t, newSrv(t, Config{MaxRequests: 1}), w2.Bytes())
	q, e = x.Next()
	mustTest(t, e)
	mustTest(t, q.Approve())
	mustTest(t, q.SendSuccess())
	mustTest(t, q.Finish())
	if _, e = x.Next(); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}
func TestErrorEOFAndReject(t *testing.T) {
	for _, cmd := range []byte{1, 5} {
		var wire bytes.Buffer
		w := recordWriter{dst: &wire, psk: []byte(testPSK)}
		mustTest(t, w.packet(requestBytes(cmd, Address{"x", 1}, nil)))
		x, m := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
		q, e := x.Next()
		mustTest(t, e)
		mustTest(t, q.CloseWrite())
		r := responseReader(t, m.out.Bytes())
		p, e := r.next()
		mustTest(t, e)
		expected := errorReply(0x65, "Remote EOF")
		if cmd == 1 {
			expected = errorReply(0xff, "end of file")
		}
		if !bytes.Equal(p, expected) {
			t.Fatal(p)
		}
		if !m.closed {
			t.Fatal("not closed")
		}
	}
	x, m := captureAccept(t, newSrv(t, Config{}), wireFile(t, "peer-connect"))
	q, e := x.Next()
	mustTest(t, e)
	mustTest(t, q.Reject(7, "refused"))
	r := responseReader(t, m.out.Bytes())
	p, e := r.next()
	mustTest(t, e)
	if !bytes.Equal(p, errorReply(7, "refused")) {
		t.Fatal(p)
	}
}
func TestDatagramAddressesAndBoundaries(t *testing.T) {
	packets := [][]byte{{1, 0, 4, 192, 0, 2, 1, 0, 53, 1, 2}, {1, 0, 6, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x14, 0xe9}, {1, 3, 'u', 'd', 'p', 0, 53, 9}}
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet([]byte{1, 6, 0}))
	for _, p := range packets {
		mustTest(t, w.packet(p))
	}
	x, m := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
	q, e := x.Next()
	mustTest(t, e)
	mustTest(t, q.Approve())
	for i, host := range []string{"192.0.2.1", "2001:db8::1", "udp"} {
		a, p, e := q.ReadDatagram()
		mustTest(t, e)
		if a.Host != host {
			t.Fatal(a)
		}
		want := []byte{1, 2}
		if i == 1 {
			want = nil
		}
		if i == 2 {
			want = []byte{9}
		}
		if !bytes.Equal(p, want) {
			t.Fatal(p)
		}
		mustTest(t, q.WriteDatagram(Address{"2001:db8::9", 123}, p))
	}
	if e = q.WriteDatagram(Address{"udp.example", 123}, nil); e != ErrProtocol {
		t.Fatal(e)
	}
	if e = q.WriteDatagram(Address{"::1", 123}, make([]byte, MaxPayload)); e != ErrLimit {
		t.Fatal(e)
	}
	r := responseReader(t, m.out.Bytes())
	b, e := r.next()
	mustTest(t, e)
	if !bytes.Equal(b, []byte{0}) {
		t.Fatal(b)
	}
	for i := 0; i < 3; i++ {
		b, e = r.next()
		mustTest(t, e)
		if b[0] != 6 || len(b) < 19 {
			t.Fatal(b)
		}
	}
	for _, p := range [][]byte{nil, {2, 1}, {1, 0, 5}, {1, 255}, {1, 0, 4, 1}, {1, 1, 'x', 0, 0}} {
		if _, _, e := parseDatagram(p); e == nil {
			t.Fatal(p)
		}
	}
}
func TestCancellationAndSlotRecovery(t *testing.T) {
	s := newSrv(t, Config{MaxSessions: 1})
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := s.AcceptContext(ctx, a); done <- e }()
	time.Sleep(10 * time.Millisecond)
	c, d := net.Pipe()
	defer d.Close()
	if _, e := s.Accept(c); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel stuck")
	}
	if len(s.slots) != 0 {
		t.Fatal("slot leak")
	}
	a, b = net.Pipe()
	defer b.Close()
	mustTest(t, a.SetDeadline(time.Now().Add(20*time.Millisecond)))
	if _, e := s.Accept(a); e == nil {
		t.Fatal("deadline ignored")
	}
	if len(s.slots) != 0 {
		t.Fatal("slot leak")
	}
}
func TestHTTPHeaderBoundsAndFragmentedTransport(t *testing.T) {
	s := newSrv(t, Config{Obfs: "http"})
	x, _ := captureAccept(t, s, append([]byte("GET / HTTP/1.1\r\nHost: fixture\r\n\r\n"), wireFile(t, "peer-connect")...))
	q, e := x.Next()
	mustTest(t, e)
	got, e := io.ReadAll(q)
	mustTest(t, e)
	if len(got) != 30018 {
		t.Fatal(len(got))
	}
	bad := &memConn{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), 8193))}
	if _, e = s.Accept(bad); e != ErrLimit {
		t.Fatal(e)
	}
	// One-byte reads split salt, headers, padding, and tags, independent of records.
	wire := wireFile(t, "peer-connect")
	m := &fragmentConn{Reader: bytes.NewReader(wire)}
	ss, e := newSrv(t, Config{}).Accept(m)
	mustTest(t, e)
	defer ss.Close()
	q, e = ss.Next()
	mustTest(t, e)
	got, e = io.ReadAll(q)
	mustTest(t, e)
	if len(got) != 30018 {
		t.Fatal(len(got))
	}
}

type fragmentConn struct{ *bytes.Reader }

func (f *fragmentConn) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return f.Reader.Read(p)
}
func (f *fragmentConn) Write(p []byte) (int, error) { return len(p), nil }
func (f *fragmentConn) Close() error                { return nil }
func TestDynamicRecordBounds(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	p := bytes.Repeat([]byte("x"), 1024*1024)
	n, e := w.stream(p)
	mustTest(t, e)
	if n != len(p) {
		t.Fatal(n)
	}
	r := responseReader(t, wire.Bytes())
	total := 0
	first := true
	for total < len(p) {
		b, e := r.next()
		mustTest(t, e)
		if first {
			if len(b) < 894 || len(b) > 1149 {
				t.Fatal(len(b))
			}
			first = false
		}
		total += len(b)
		if len(b) > MaxPayload {
			t.Fatal(len(b))
		}
	}
	if total != len(p) {
		t.Fatal(total)
	}
	w.last = time.Now().Add(-32 * time.Second)
	w.batchLeft = 0
	if w.ceiling(time.Now()) != 1421 {
		t.Fatal("idle reset")
	}
}

// TestIndependentPeer launches the fixed isolated GPL client subprocess. It uses
// only loopback ephemeral ports and no real target dialing. Destinations are
// returned to the test core, which supplies deterministic application behavior.
func TestIndependentPeer(t *testing.T) {
	binary := os.Getenv("KAT_SNELL_LIBRARY_PEER")
	if binary == "" {
		t.Skip("set KAT_SNELL_LIBRARY_PEER to isolated peer/client")
	}
	binary, e := filepath.Abs(binary)
	mustTest(t, e)
	for _, mode := range []string{"none", "http"} {
		t.Run(mode, func(t *testing.T) {
			ln, e := net.Listen("tcp", "127.0.0.1:0")
			mustTest(t, e)
			defer ln.Close()
			server := newSrv(t, Config{Obfs: mode})
			var wg sync.WaitGroup
			var mu sync.Mutex
			var sessions []*Session
			var targets []string
			accepts := 0
			fail := make(chan error, 8)
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					c, e := ln.Accept()
					if e != nil {
						return
					}
					mu.Lock()
					accepts++
					mu.Unlock()
					wg.Add(1)
					go func() {
						defer wg.Done()
						c.SetDeadline(time.Now().Add(12 * time.Second))
						ss, e := server.Accept(c)
						if e != nil {
							fail <- e
							return
						}
						mu.Lock()
						sessions = append(sessions, ss)
						mu.Unlock()
						defer ss.Close()
						for {
							q, e := ss.Next()
							if e != nil {
								if e != io.EOF && !errors.Is(e, net.ErrClosed) {
									fail <- e
								}
								return
							}
							if e = q.Approve(); e != nil {
								fail <- e
								return
							}
							if q.Command == UDP {
								if e = q.SendSuccess(); e != nil {
									fail <- e
									return
								}
								for i := 0; i < 3; i++ {
									a, p, e := q.ReadDatagram()
									if e != nil {
										fail <- e
										return
									}
									mu.Lock()
									targets = append(targets, "udp:"+a.String())
									mu.Unlock()
									if e = q.WriteDatagram(Address{"192.0.2.9", 9000}, p); e != nil {
										fail <- e
										return
									}
								}
								return
							}
							mu.Lock()
							targets = append(targets, q.Target.String())
							mu.Unlock()
							if _, e = q.Write([]byte("hello:" + q.Target.String() + ":")); e != nil {
								fail <- e
								return
							}
							if _, e = io.Copy(q, q); e != nil {
								fail <- e
								return
							}
							if e = q.Finish(); e != nil {
								fail <- e
								return
							}
						}
					}()
				}
			}()
			peerCtx, stopPeer := context.WithTimeout(context.Background(), 20*time.Second)
			defer stopPeer()
			cmd := exec.CommandContext(peerCtx, binary, ln.Addr().String(), mode)
			cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
			out, e := cmd.CombinedOutput()
			ln.Close()
			<-acceptDone
			mu.Lock()
			for _, ss := range sessions {
				ss.Close()
			}
			mu.Unlock()
			wg.Wait()
			close(fail)
			t.Logf("peer output:\n%s", out)
			if e != nil {
				t.Fatal(e)
			}
			for e := range fail {
				t.Error(e)
			}
			mu.Lock()
			defer mu.Unlock()
			if accepts != 2 {
				t.Fatalf("wanted one reused TCP session + UDP session, got %d", accepts)
			}
			expected := []string{"alpha.example:10001", "[2001:db8::2]:10002", "udp:192.0.2.1:53", "udp:[2001:db8::1]:5353", "udp:udp.example:53"}
			if fmt.Sprint(targets) != fmt.Sprint(expected) {
				t.Fatalf("targets %v", targets)
			}
			t.Logf("physical TCP=%d, request targets=%v", accepts, targets)
		})
	}
}

func TestPaddingShapingAndUnprotectedBytes(t *testing.T) {
	for _, c := range [][]byte{bytes.Repeat([]byte{0x55}, 80), bytes.Repeat([]byte{0xaa}, 79), bytes.Repeat([]byte{0}, 80), bytes.Repeat([]byte{255}, 80)} {
		b, e := shapedPadding(256, c)
		mustTest(t, e)
		if len(b) != 256 {
			t.Fatal(len(b))
		}
	}
	// Odd padding bytes are not covered by the body tag in this wire. Demonstrate
	// the limitation instead of claiming universal padding authentication.
	b := wireFile(t, "peer-connect")
	b[40] ^= 1
	x, _ := captureAccept(t, newSrv(t, Config{}), b)
	q, e := x.Next()
	mustTest(t, e)
	got, e := io.ReadAll(q)
	mustTest(t, e)
	if len(got) != 30018 {
		t.Fatal(len(got))
	}
}
func TestActiveCancelAndHalfCloseIdempotence(t *testing.T) {
	s := newSrv(t, Config{MaxSessions: 1})
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		ss, e := s.AcceptContext(ctx, a)
		if e != nil {
			done <- e
			return
		}
		defer ss.Close()
		q, e := ss.Next()
		if e != nil {
			done <- e
			return
		}
		_, e = io.Copy(io.Discard, q)
		done <- e
	}()
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"x", 1}, nil)))
	mustTest(t, writeAll(b, wire.Bytes()))
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancel did not abort read")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel failed")
	}
	if len(s.slots) != 0 {
		t.Fatal("slot leak")
	}
	var stream bytes.Buffer
	wr := recordWriter{dst: &stream, psk: []byte(testPSK)}
	mustTest(t, wr.packet(requestBytes(5, Address{"x", 1}, nil)))
	mustTest(t, wr.end())
	ss, m := captureAccept(t, s, stream.Bytes())
	q, e := ss.Next()
	mustTest(t, e)
	mustTest(t, q.Approve())
	mustTest(t, q.SendSuccess())
	mustTest(t, q.CloseWrite())
	before := m.out.Len()
	mustTest(t, q.CloseWrite())
	if m.out.Len() != before {
		t.Fatal("duplicate zero")
	}
	p := make([]byte, 1)
	if _, e = q.Read(p); e != io.EOF {
		t.Fatal(e)
	}
	if _, e = q.Read(p); e != io.EOF {
		t.Fatal(e)
	}
	mustTest(t, q.Finish())
}
func TestPhysicalEOFNotLogicalZero(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"x", 1}, nil)))
	ss, m := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
	q, e := ss.Next()
	mustTest(t, e)
	if _, e = q.Read(make([]byte, 1)); e != io.ErrUnexpectedEOF {
		t.Fatal(e)
	}
	if !m.closed {
		t.Fatal("physical EOF must abort")
	}
}
func TestLiveServerFirstAndResponseHalfClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan error, 1)
	s := newSrv(t, Config{})
	go func() {
		ss, e := s.Accept(a)
		if e != nil {
			done <- e
			return
		}
		defer ss.Close()
		q, e := ss.Next()
		if e != nil {
			done <- e
			return
		}
		if e = q.Approve(); e == nil {
			_, e = q.Write([]byte("greeting"))
		}
		if e == nil {
			e = q.CloseWrite()
		}
		if e == nil {
			_, e = io.Copy(io.Discard, q)
		}
		if e == nil {
			e = q.Finish()
		}
		done <- e
	}()
	mustTest(t, b.SetDeadline(time.Now().Add(3*time.Second)))
	w := recordWriter{dst: b, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"mail.example", 25}, nil)))
	var salt [16]byte
	_, e := io.ReadFull(b, salt[:])
	mustTest(t, e)
	aa, e := aeadFor([]byte(testPSK), salt[:])
	mustTest(t, e)
	r := recordReader{src: b, a: aa}
	p, e := r.next()
	mustTest(t, e)
	if string(p) != "\x00greeting" {
		t.Fatal(p)
	}
	if _, e = r.next(); e != io.EOF {
		t.Fatal(e)
	}
	// Server output is half-closed; client input can still carry data up to zero.
	_, e = w.stream([]byte("client after server EOF"))
	mustTest(t, e)
	mustTest(t, w.end())
	mustTest(t, <-done)
}

func TestLaterBadTagCannotAdvanceReuse(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"old", 1}, nil)))
	offset := wire.Len()
	mustTest(t, w.packet([]byte("tail")))
	mustTest(t, w.end())
	mustTest(t, w.packet(requestBytes(5, Address{"new", 2}, nil)))
	b := bytes.Clone(wire.Bytes())
	b[offset+23+4] ^= 0x80
	ss, m := captureAccept(t, newSrv(t, Config{}), b)
	q, e := ss.Next()
	mustTest(t, e)
	if _, e = q.Read(make([]byte, 10)); e == nil {
		t.Fatal("bad body tag accepted")
	}
	if !m.closed {
		t.Fatal("not closed")
	}
	if _, e = ss.Next(); e == nil {
		t.Fatal("advanced after bad tag")
	}
}
func TestShortWritesAndCounterBound(t *testing.T) {
	var b bytes.Buffer
	w := recordWriter{dst: &shortWriter{&b}, psk: []byte(testPSK)}
	mustTest(t, w.packet([]byte("short writer")))
	r := responseReader(t, b.Bytes())
	p, e := r.next()
	mustTest(t, e)
	if string(p) != "short writer" {
		t.Fatal(p)
	}
	w.counter = ^uint64(0)
	if e = w.end(); e != ErrLimit {
		t.Fatal(e)
	}
	r.counter = ^uint64(0)
	if _, e = r.open(make([]byte, 23)); e != ErrLimit {
		t.Fatal(e)
	}
	if e = writeAll(zeroWriter{}, []byte{1}); e != io.ErrShortWrite {
		t.Fatal(e)
	}
}

type shortWriter struct{ w io.Writer }

func (s *shortWriter) Write(p []byte) (int, error) { return s.w.Write(p[:min(len(p), 3)]) }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func TestDrainCancellationAndRecordBudget(t *testing.T) {
	var wire bytes.Buffer
	w := recordWriter{dst: &wire, psk: []byte(testPSK)}
	mustTest(t, w.packet(requestBytes(5, Address{"x", 1}, nil)))
	for i := 0; i < 1025; i++ {
		mustTest(t, w.packet([]byte{1}))
	}
	mustTest(t, w.end())
	ss, _ := captureAccept(t, newSrv(t, Config{}), wire.Bytes())
	q, e := ss.Next()
	mustTest(t, e)
	mustTest(t, q.Approve())
	mustTest(t, q.SendSuccess())
	if e = q.Finish(); e != ErrLimit {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	defer b.Close()
	s := newSrv(t, Config{MaxSessions: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		ss, e := s.AcceptContext(ctx, a)
		if e != nil {
			done <- e
			return
		}
		defer ss.Close()
		q, e := ss.Next()
		if e != nil {
			done <- e
			return
		}
		e = q.Approve()
		if e == nil {
			e = q.SendSuccess()
		}
		if e != nil {
			done <- e
			return
		}
		close(ready)
		done <- q.Finish()
	}()
	mustTest(t, b.SetDeadline(time.Now().Add(3*time.Second)))
	client := recordWriter{dst: b, psk: []byte(testPSK)}
	mustTest(t, client.packet(requestBytes(5, Address{"x", 1}, nil)))
	var salt [16]byte
	_, e = io.ReadFull(b, salt[:])
	mustTest(t, e)
	aa, e := aeadFor([]byte(testPSK), salt[:])
	mustTest(t, e)
	rr := recordReader{src: b, a: aa}
	_, e = rr.next()
	mustTest(t, e)
	<-ready
	if _, e = rr.next(); e != io.EOF {
		t.Fatal(e)
	}
	cancel()
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("drain cancel ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("drain stuck")
	}
	if len(s.slots) != 0 {
		t.Fatal("slot leak")
	}
}

func TestInvalidContextStillOwnsTransport(t *testing.T) {
	s := newSrv(t, Config{})
	m := &memConn{Reader: bytes.NewReader(nil)}
	if _, e := s.AcceptContext(nil, m); e != ErrState || !m.closed || len(s.slots) != 0 {
		t.Fatal(e, m.closed, len(s.slots))
	}
}
