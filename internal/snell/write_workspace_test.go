package snell

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Frozen 0.5.3 frame reference. Only tests use predictable entropy; production
// crypto/rand and the padding/KDF implementation are never altered.
func legacySealForTest(w *recordWriter, p []byte) ([]byte, error) {
	if w.counter == math.MaxUint64 {
		return nil, ErrLimit
	}
	var n [12]byte
	binary.LittleEndian.PutUint64(n[:8], w.counter)
	w.counter++
	return w.a.Seal(nil, n[:], p, nil), nil
}
func legacyFrameForTest(w *recordWriter, p []byte) error {
	if len(p) > MaxPayload {
		return ErrLimit
	}
	if e := w.init(); e != nil {
		return e
	}
	pad := 0
	if !w.started && len(p) > 0 {
		pad = w.padding
	}
	h := []byte{4, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[3:5], uint16(pad))
	binary.BigEndian.PutUint16(h[5:7], uint16(len(p)))
	head, e := legacySealForTest(w, h)
	if e != nil {
		return e
	}
	var out []byte
	if !w.started {
		out = append(out, w.salt[:]...)
	}
	out = append(out, head...)
	if len(p) > 0 {
		c, e := legacySealForTest(w, p)
		if e != nil {
			return e
		}
		padding, e := shapedPadding(pad, c)
		if e != nil {
			return e
		}
		for i := 0; i < min(pad, len(c)); i += 2 {
			padding[i], c[i] = c[i], padding[i]
		}
		out = append(out, padding...)
		out = append(out, c...)
	}
	w.started = true
	return writeAll(w.dst, out)
}
func TestWriterWireExactAgainst053Reference(t *testing.T) {
	old := crand.Reader
	defer func() { crand.Reader = old }()
	sequences := [][][]byte{{bytes.Repeat([]byte{0x11}, 117), bytes.Repeat([]byte{0x22}, 1024), bytes.Repeat([]byte{0x44}, MaxPayload), nil, []byte("new-target"), bytes.Repeat([]byte{0x33}, 8192)}, {nil, bytes.Repeat([]byte{0x55}, 4096), nil}}
	for i, seq := range sequences {
		var a, b bytes.Buffer
		wa := recordWriter{dst: &a, psk: []byte(testPSK)}
		wb := recordWriter{dst: &b, psk: []byte(testPSK)}
		crand.Reader = mrand.New(mrand.NewSource(int64(1053 + i)))
		for _, p := range seq {
			if e := legacyFrameForTest(&wa, p); e != nil {
				t.Fatal(e)
			}
		}
		crand.Reader = mrand.New(mrand.NewSource(int64(1053 + i)))
		for _, p := range seq {
			if e := wb.frame(p); e != nil {
				t.Fatal(e)
			}
		}
		if !bytes.Equal(a.Bytes(), b.Bytes()) || wa.counter != wb.counter || wa.started != wb.started || wa.salt != wb.salt {
			t.Fatal("wire/nonce/salt drift", i, wa.counter, wb.counter)
		}
		r := responseReader(t, b.Bytes())
		for _, want := range seq {
			got, e := r.next()
			if len(want) == 0 {
				if e != io.EOF || !r.zero {
					t.Fatal("zero boundary changed", e)
				}
			} else if e != nil || !bytes.Equal(got, want) {
				t.Fatal("independent decode", e)
			}
		}
	}
}

type scheduledWriter struct {
	bytes.Buffer
	limit, failAfter int
	zero             bool
}

func (w *scheduledWriter) Write(p []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	if w.failAfter >= 0 && w.Buffer.Len() >= w.failAfter {
		return 0, io.ErrClosedPipe
	}
	n := min(len(p), w.limit)
	if w.failAfter >= 0 {
		n = min(n, w.failAfter-w.Buffer.Len())
	}
	w.Buffer.Write(p[:n])
	if w.failAfter >= 0 && w.Buffer.Len() >= w.failAfter {
		return n, io.ErrClosedPipe
	}
	return n, nil
}
func presetWriter(t *testing.T, dst io.Writer, counter uint64) *recordWriter {
	t.Helper()
	a, e := aeadFor([]byte(testPSK), bytes.Repeat([]byte{9}, 16))
	if e != nil {
		t.Fatal(e)
	}
	return &recordWriter{dst: dst, psk: []byte(testPSK), a: a, started: true, counter: counter, padding: 256}
}
func TestWriterShortErrorNonceEquivalentTo053(t *testing.T) {
	for _, count := range []uint64{0, math.MaxUint64 - 1, math.MaxUint64} {
		for _, mode := range []int{0, 1, 2} {
			a := &scheduledWriter{limit: 3, failAfter: -1}
			b := &scheduledWriter{limit: 3, failAfter: -1}
			if mode == 1 {
				a.failAfter = 31
				b.failAfter = 31
			}
			if mode == 2 {
				a.zero = true
				b.zero = true
			}
			wa, wb := presetWriter(t, a, count), presetWriter(t, b, count)
			p := bytes.Repeat([]byte{0x21}, 8192)
			ea, eb := legacyFrameForTest(wa, p), wb.frame(p)
			if !errors.Is(ea, eb) || !bytes.Equal(a.Bytes(), b.Bytes()) || wa.counter != wb.counter || wa.started != wb.started {
				t.Fatal("error/partial/nonce state changed", count, mode, ea, eb)
			}
		}
	}
}
func TestWriterCacheLimitClearExclusive(t *testing.T) {
	var held [][]byte
	for i := 0; i < 40; i++ {
		p := takeWriteBuffer(MaxPayload + 39)
		for j := range p {
			p[j] = 0xab
		}
		held = append(held, p)
	}
	for _, p := range held {
		releaseWriteBuffer(p)
	}
	writeBuffers.Lock()
	if len(writeBuffers.frames) > 16 || writeBuffers.bytes > 256*1024 {
		t.Fatal("cache unbounded")
	}
	seen := map[*byte]bool{}
	for _, p := range writeBuffers.frames {
		if seen[&p[0]] {
			t.Fatal("same lease cached twice")
		}
		seen[&p[0]] = true
	}
	writeBuffers.Unlock()
	p := takeWriteBuffer(MaxPayload + 39)
	q := takeWriteBuffer(MaxPayload + 39)
	if &p[0] == &q[0] || !bytes.Equal(p, make([]byte, len(p))) || !bytes.Equal(q, make([]byte, len(q))) {
		t.Fatal("ownership/clear")
	}
	releaseWriteBuffer(p)
	releaseWriteBuffer(q)
}

type blockedRecordConn struct {
	*memConn
	block   atomic.Bool
	entered chan []byte
	stop    chan struct{}
	once    sync.Once
}

func (c *blockedRecordConn) Write(p []byte) (int, error) {
	if c.block.Load() {
		c.entered <- p
		<-c.stop
		return min(17, len(p)), io.ErrClosedPipe
	}
	return c.memConn.Write(p)
}
func (c *blockedRecordConn) Close() error {
	var e error
	c.once.Do(func() { close(c.stop); e = c.memConn.Close() })
	return e
}
func TestWriterBlockedCloseDoesNotReturnInFlightBuffer(t *testing.T) {
	g := &blockedRecordConn{memConn: &memConn{Reader: bytes.NewReader(wireFile(t, "peer-connect"))}, entered: make(chan []byte, 2), stop: make(chan struct{})}
	ss, e := newSrv(t, Config{}).Accept(g)
	if e != nil {
		t.Fatal(e)
	}
	defer ss.Close()
	q, e := ss.Next()
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Approve(); e != nil {
		t.Fatal(e)
	}
	if e = q.SendSuccess(); e != nil {
		t.Fatal(e)
	}
	// Simulate the existing legal 31s idle reset so the next frame is 1421B,
	// exercising the pooled path without altering production sizing or timers.
	ss.w.last = time.Now().Add(-32 * time.Second)
	g.block.Store(true)
	done := make(chan error, 1)
	go func() { _, e := q.Write(bytes.Repeat([]byte{7}, 8192)); done <- e }()
	var held []byte
	select {
	case held = <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not block")
	}
	before := bytes.Clone(held)
	other := takeWriteBuffer(len(held))
	if &held[0] == &other[0] {
		t.Fatal("inflight buffer was reused")
	}
	for i := range other {
		other[i] = 0xee
	}
	releaseWriteBuffer(other)
	if !bytes.Equal(held, before) {
		t.Fatal("other writer corrupted in-flight cipher")
	}
	q.Close()
	if e = <-done; e == nil {
		t.Fatal("partial IO silently succeeded")
	}
	if !bytes.Equal(held[:cap(held)], make([]byte, cap(held))) {
		t.Fatal("failed frame not fully cleared")
	}
}
func TestWriterConcurrentPSKSessions(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			psk := bytes.Repeat([]byte{byte(i + 1)}, 24)
			salt := bytes.Repeat([]byte{byte(i + 31)}, 16)
			a, e := aeadFor(psk, salt)
			if e != nil {
				t.Error(e)
				return
			}
			var out bytes.Buffer
			w := recordWriter{dst: &out, psk: psk, a: a, started: true}
			payload := bytes.Repeat([]byte{byte(61 + i)}, MaxPayload)
			for n := 0; n < 12; n++ {
				if e = w.frame(payload); e != nil {
					t.Error(e)
					return
				}
			}
			dec, e := aeadFor(psk, salt)
			if e != nil {
				t.Error(e)
				return
			}
			r := recordReader{src: bytes.NewReader(out.Bytes()), a: dec}
			for n := 0; n < 12; n++ {
				got, e := r.next()
				if e != nil || !bytes.Equal(got, payload) {
					t.Error("PSK/session output crossed", e)
					return
				}
			}
		}()
	}
	wg.Wait()
}

var _ cipher.AEAD
