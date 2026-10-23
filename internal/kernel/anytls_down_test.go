package kernel

import (
	"bytes"
	"errors"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type anyTLSDownTestConn struct {
	net.Conn
	reader   io.Reader
	output   bytes.Buffer
	writes   []int
	writeErr error
	short    bool
}

func (c *anyTLSDownTestConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *anyTLSDownTestConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.short {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}

type anyTLSDownTail struct{}

func (anyTLSDownTail) Read(p []byte) (int, error) { return copy(p, "tail"), io.ErrUnexpectedEOF }

func TestAnyTLSDownFallbackAndErrors(t *testing.T) {
	payload := bytes.Repeat([]byte("download"), 20000)
	for _, size := range []int{1024, 16384, 65536} {
		s := &Server{pool: newBufferPool(size, 1)}
		src := &anyTLSDownTestConn{reader: bytes.NewReader(payload)}
		dst := new(anyTLSDownTestConn)
		if err := s.copyAnyTLSDown(dst, src, src); err != nil || !bytes.Equal(dst.output.Bytes(), payload) {
			t.Fatalf("size=%d err=%v", size, err)
		}
		for _, n := range dst.writes {
			if n > min(size, 16377) {
				t.Fatalf("fallback write=%d", n)
			}
		}
		owner := s.pool.get()
		if len(owner) != size || cap(owner) != size || !bytes.Equal(owner, make([]byte, size)) {
			t.Fatal("original pool allocation not returned/cleared")
		}
		s.pool.put(owner)
	}
	s := &Server{pool: newBufferPool(16384, 1)}
	src := &anyTLSDownTestConn{reader: anyTLSDownTail{}}
	dst := new(anyTLSDownTestConn)
	if err := s.copyAnyTLSDown(dst, src, src); !errors.Is(err, io.ErrUnexpectedEOF) || dst.output.String() != "tail" {
		t.Fatalf("tail err=%v out=%q", err, dst.output.String())
	}
	for _, dst = range []*anyTLSDownTestConn{{short: true}, {writeErr: io.ErrClosedPipe}} {
		src = &anyTLSDownTestConn{reader: bytes.NewReader(payload)}
		err := s.copyAnyTLSDown(dst, src, src)
		if dst.short && !errors.Is(err, io.ErrShortWrite) || dst.writeErr != nil && !errors.Is(err, dst.writeErr) {
			t.Fatalf("write error=%v", err)
		}
	}
}
func TestAnyTLSDownLeaseBoundedCleared(t *testing.T) {
	held := make([][]byte, 0, anyTLSDownLeases)
	for i := 0; i < anyTLSDownLeases; i++ {
		b := leaseAnyTLSDown()
		if len(b) != anyTLSDownBytes || cap(b) != anyTLSDownBytes {
			t.Fatal("lease size")
		}
		b[0] = 1
		b[len(b)-1] = 1
		held = append(held, b)
	}
	if leaseAnyTLSDown() != nil {
		t.Fatal("lease bound exceeded")
	}
	for _, b := range held {
		releaseAnyTLSDown(b)
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("lease not cleared")
		}
	}
}
func TestAnyTLSDownReadyCoalescesAndReleases(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	} // unknown readiness uses fallback, tested above
	payload := bytes.Repeat([]byte("hot-target"), 10000)
	for _, mode := range []string{"success", "write-error", "no-lease"} {
		reader, writer := ss2017TCPPair(t)
		reader.SetDeadline(time.Now().Add(3 * time.Second))
		writer.SetDeadline(time.Now().Add(3 * time.Second))
		sent := make(chan error, 1)
		go func() { _, err := writer.Write(payload); writer.CloseWrite(); sent <- err }()
		end := time.Now().Add(time.Second)
		for ss2022Ready(reader) < 32768 && time.Now().Before(end) {
			time.Sleep(time.Millisecond)
		}
		if ss2022Ready(reader) < 32768 {
			t.Fatal("target bytes not queued")
		}
		var held [][]byte
		if mode == "no-lease" {
			for i := 0; i < anyTLSDownLeases; i++ {
				held = append(held, leaseAnyTLSDown())
			}
		}
		s := &Server{pool: newBufferPool(16384, 1)}
		dst := new(anyTLSDownTestConn)
		if mode == "write-error" {
			dst.writeErr = io.ErrClosedPipe
		}
		var last atomic.Int64
		err := s.copyAnyTLSDown(dst, &activityStream{reader, &last}, reader)
		for _, b := range held {
			releaseAnyTLSDown(b)
		}
		reader.Close()
		if e := <-sent; e != nil {
			t.Fatal(e)
		}
		if mode == "write-error" {
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
		} else if err != nil || !bytes.Equal(dst.output.Bytes(), payload) {
			t.Fatalf("%s err=%v bytes=%d", mode, err, dst.output.Len())
		}
		maxWrite := 0
		for _, n := range dst.writes {
			maxWrite = max(maxWrite, n)
			if n > anyTLSDownBytes {
				t.Fatalf("oversized write=%d", n)
			}
		}
		if mode != "no-lease" && maxWrite <= 16377 {
			t.Fatalf("did not coalesce: %v", dst.writes)
		}
		if mode == "no-lease" && maxWrite > 16377 {
			t.Fatal("fallback exceeded read view")
		}
		if len(anyTLSDownSlots) != 0 {
			t.Fatal("lease leaked")
		}
		if last.Load() == 0 {
			t.Fatal("idle activity not recorded")
		}
	}
}

func TestAnyTLSOwnedRejectedWireClearedBeforePoolReturn(t *testing.T) {
	// A zero-value stream rejects this short frame before accessing session;
	// the codec clears the FULL capacity before the pool callback runs.
	b := leaseAnyTLSDown()
	for i := range b {
		b[i] = 0x55
	}
	var stream A.Stream
	// A short wire (<7) exercises the same dispose callback on rejection.
	_, err := stream.WriteOwnedFrame(b[:6], returnClearedAnyTLSDown)
	if err == nil {
		t.Fatal("expected format/queue rejection")
	}
	if len(anyTLSDownSlots) != 0 || !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("returned buffer before complete clear")
	}
}
