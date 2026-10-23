package anytls

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"
)

func TestOwnedAbsoluteWatchdogRetainsInflightOwnership(t *testing.T) {
	tr := &ownedBlockedTransport{entered: make(chan struct{}), unblock: make(chan struct{})}
	s, st := ownedSession(t, tr, 25*time.Millisecond)
	wire := bytes.Repeat([]byte{0x39}, 65528)
	released := make(chan struct{})
	result := make(chan error, 1)
	go s.writeLoop()
	go func() {
		_, e := st.WriteOwnedFrame(wire, func(b []byte) {
			if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
				t.Error("not cleared")
			}
			close(released)
		})
		result <- e
	}()
	defer func() { s.fail(context.Canceled) }()
	<-tr.entered
	select {
	case e := <-result:
		if !errors.Is(e, ErrWriteTimeout) {
			t.Error(e)
		}
	case <-time.After(time.Second):
		close(tr.unblock)
		<-s.writerDone
		t.Fatal("absolute sender timer did not abort blocked I/O")
	}
	s.mu.Lock()
	charged := s.outBytes
	s.mu.Unlock()
	if charged != cap(wire) {
		t.Error("inflight uncharged", charged)
	}
	select {
	case <-released:
		t.Error("released before I/O")
	default:
	}
	close(tr.unblock)
	select {
	case <-s.writerDone:
	case <-time.After(time.Second):
		t.Fatal("writer did not join")
	}
	select {
	case <-released:
	default:
		t.Fatal("ownership leaked")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outBytes != 0 || s.outFrames != 0 {
		t.Fatal("accounting leaked")
	}
}

func TestOwnedWatchdogMetadataFitsExistingFrame(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(outbound{}) > 64 {
		t.Fatal("owned watchdog grew per-frame metadata", unsafe.Sizeof(outbound{}))
	}
}
