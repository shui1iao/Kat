package anytls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
	"unsafe"
)

func TestOwnedWriteTimerReuseClearsOwnerAndNoStaleCancel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s, _ := ownedSession(t, a, time.Second)
	for i := 0; i < 100; i++ {
		w := acquireOwnedWriteTimer(s, time.Now().Add(time.Second))
		if w.owner != s {
			t.Fatal("wrong owner")
		}
		if !stopOwnedWriteTimer(w) {
			t.Fatal("early timeout")
		}
		if w.owner != nil {
			t.Fatal("retained session")
		}
	}
	if s.ctx.Err() != nil {
		t.Fatal("stale callback cancelled session")
	}
	//16*512B conservative timer wrapper/runtime/closure allowance +16*384B
	// descriptor/channel allowance +512B cache channels < existing16KiB reserve.
	if 16*512+16*384+512 > OwnedMetadataReservedBytes || unsafe.Sizeof(ownedWriteTimer{}) > 64 {
		t.Fatal("metadata reserve exceeded")
	}
	allocs := testing.AllocsPerRun(100, func() {
		w := acquireOwnedWriteTimer(s, time.Now().Add(time.Hour))
		if !stopOwnedWriteTimer(w) {
			panic("timer")
		}
	})
	if allocs != 0 {
		t.Fatalf("cached timer allocs %v", allocs)
	}
}

type blockedCloseForTimer struct{ entered, release chan struct{} }

func (c *blockedCloseForTimer) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *blockedCloseForTimer) Write(p []byte) (int, error) { return len(p), nil }
func (c *blockedCloseForTimer) Close() error                { close(c.entered); <-c.release; return nil }
func TestOwnedWriteTimerFiredCallbackNeverReused(t *testing.T) {
	tr := &blockedCloseForTimer{make(chan struct{}), make(chan struct{})}
	s, _ := ownedSession(t, tr, time.Second)
	w := acquireOwnedWriteTimer(s, time.Now())
	select {
	case <-tr.entered:
	case <-time.After(time.Second):
		t.Fatal("callback missing")
	}
	if stopOwnedWriteTimer(w) {
		t.Fatal("active callback reused")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	other, _ := ownedSession(t, a, time.Second)
	next := acquireOwnedWriteTimer(other, time.Now().Add(time.Hour))
	if next == w {
		t.Fatal("callback timer assigned to new session")
	}
	if !stopOwnedWriteTimer(next) {
		t.Fatal("unexpected expiry")
	}
	close(tr.release)
	if other.ctx.Err() != nil {
		t.Fatal("cross-session stale cancel")
	}
	if context.Cause(s.ctx) != ErrWriteTimeout {
		t.Fatal("absolute timeout not preserved")
	}
}
func BenchmarkOwnedWatchdog(b *testing.B) {
	a, c := net.Pipe()
	defer a.Close()
	defer c.Close()
	cfg := cfg()
	srv, _ := NewServer(cfg)
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &session{server: srv, transport: a, ctx: ctx, cancel: cancel}
	end := time.Now().Add(time.Hour)
	b.Run("old-AfterFunc", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			timer := time.AfterFunc(time.Until(end), func() { s.fail(ErrWriteTimeout) })
			if !timer.Stop() {
				b.Fatal("expiry")
			}
		}
	})
	b.Run("bounded-reuse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			w := acquireOwnedWriteTimer(s, end)
			if !stopOwnedWriteTimer(w) {
				b.Fatal("expiry")
			}
		}
	})
}
