package anytls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type watchdogFiredTransport struct {
	entered, callbackClose, finishWrite chan struct{}
	calls                               atomic.Int32
	closeOnce                           sync.Once
}

func (c *watchdogFiredTransport) Read([]byte) (int, error) { return 0, io.EOF }
func (c *watchdogFiredTransport) Write(p []byte) (int, error) {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		<-c.finishWrite
	}
	return len(p), nil // deliberately successful late I/O after watchdog fired
}
func (c *watchdogFiredTransport) Close() error {
	c.closeOnce.Do(func() { close(c.callbackClose) })
	return nil
}

func TestWriterWatchdogFiredNeverReusedForQueuedFrame(t *testing.T) {
	tr := &watchdogFiredTransport{entered: make(chan struct{}), callbackClose: make(chan struct{}), finishWrite: make(chan struct{})}
	s, st := ownedSession(t, tr, 20*time.Millisecond)
	// Directly queue two fully charged frames. No send() timer can cancel this
	// session: callbackClose proves it was writeLoop's AfterFunc that fired.
	wires := [][]byte{bytes.Repeat([]byte{0x53}, 64), bytes.Repeat([]byte{0x54}, 96)}
	releases := [2]atomic.Int32{}
	frames := make([]*outbound, 2)
	for i, wire := range wires {
		idx := i
		frames[i] = &outbound{wire: wire, cost: cap(wire), stream: st, done: make(chan error, 1), release: func(b []byte) {
			if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
				t.Error("released before full clear")
			}
			releases[idx].Add(1)
		}}
	}
	s.out = append([]*outbound(nil), frames...)
	s.outFrames = 2
	st.outFrames = 2
	s.outBytes = 160
	st.outBytes = 160
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(tr.finishWrite) }) }
	go s.writeLoop()
	defer func() {
		release()
		s.fail(context.Canceled)
		select {
		case <-s.writerDone:
		case <-time.After(time.Second):
			t.Error("writer did not join")
		}
	}()
	select {
	case <-tr.entered:
	case <-time.After(time.Second):
		t.Fatal("I/O not entered")
	}
	select {
	case <-tr.callbackClose:
	case <-time.After(time.Second):
		t.Fatal("watchdog callback did not fire")
	}
	if !errors.Is(context.Cause(s.ctx), ErrWriteTimeout) {
		t.Fatal(context.Cause(s.ctx))
	}
	// Callback has begun, so this exact watchdog Stop MUST return false when
	// successful target I/O is allowed to finish. The queued frame cannot reset it.
	s.mu.Lock()
	charged, queued := s.outBytes, s.outFrames
	s.mu.Unlock()
	if charged != 160 || queued != 2 || releases[0].Load() != 0 || releases[1].Load() != 0 {
		t.Fatal("inflight ownership lost before I/O return", charged, queued)
	}
	if !bytes.Equal(wires[0], bytes.Repeat([]byte{0x53}, 64)) {
		t.Fatal("inflight data cleared")
	}
	release()
	select {
	case <-s.writerDone:
	case <-time.After(time.Second):
		t.Fatal("Stop=false path failed to terminate")
	}
	if tr.calls.Load() != 1 {
		t.Fatal("queued frame written after fired watchdog", tr.calls.Load())
	}
	if e := <-frames[0].done; e != nil {
		t.Fatal("late successful I/O result changed", e)
	}
	if e := <-frames[1].done; !errors.Is(e, ErrWriteTimeout) {
		t.Fatal("queued frame not failed with watchdog cause", e)
	}
	if releases[0].Load() != 1 || releases[1].Load() != 1 {
		t.Fatal("release not exactly once")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outBytes != 0 || s.outFrames != 0 || st.outBytes != 0 || st.outFrames != 0 || len(s.out) != 0 {
		t.Fatal("writer teardown leaked accounting")
	}
}
