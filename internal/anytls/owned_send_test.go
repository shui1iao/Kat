package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"
)

type ownedBlockedTransport struct {
	entered chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func (c *ownedBlockedTransport) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *ownedBlockedTransport) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.unblock
	return len(p), nil
}
func (c *ownedBlockedTransport) Close() error { return nil } // deliberately late I/O completion

func ownedSession(t *testing.T, tr io.ReadWriteCloser, timeout time.Duration) (*session, *Stream) {
	t.Helper()
	c := cfg()
	c.WriteTimeout = timeout
	srv, err := NewServer(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &session{server: srv, transport: tr, ctx: ctx, cancel: cancel, change: make(chan struct{}), writerDone: make(chan struct{})}
	st := &Stream{session: s, id: 19}
	return s, st
}
func TestOwnedFrameChargedUntilLateTransportReturns(t *testing.T) {
	tr := &ownedBlockedTransport{entered: make(chan struct{}), unblock: make(chan struct{})}
	s, st := ownedSession(t, tr, 30*time.Millisecond)
	wire := bytes.Repeat([]byte{0x44}, 65528)
	wire = wire[:4103]
	released := make(chan struct{})
	sent := make(chan error, 1)
	go s.writeLoop()
	go func() {
		_, err := st.WriteOwnedFrame(wire, func(b []byte) {
			if cap(b) != 65528 || !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
				t.Error("lease not fully cleared")
			}
			close(released)
		})
		sent <- err
	}()
	select {
	case <-tr.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter")
	}
	if wire[0] != cmdPSH || binary.BigEndian.Uint32(wire[1:5]) != 19 || binary.BigEndian.Uint16(wire[5:7]) != 4096 {
		t.Fatal("wire header")
	}
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("expected timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout missing")
	}
	select {
	case <-released:
		t.Fatal("returned allocation before I/O completed")
	default:
	}
	s.mu.Lock()
	charged := s.outBytes
	s.mu.Unlock()
	if charged != 65528 {
		t.Fatalf("charged=%d", charged)
	}
	close(tr.unblock)
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("release missing")
	}
	<-s.writerDone
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outBytes != 0 || st.outBytes != 0 || s.outFrames != 0 {
		t.Fatal("budget leak")
	}
}
func TestOwnedFrameQueueCancellationAndBudgetRejection(t *testing.T) {
	for _, reject := range []bool{false, true} {
		tr := &ownedBlockedTransport{entered: make(chan struct{}), unblock: make(chan struct{})}
		s, st := ownedSession(t, tr, time.Second)
		if reject {
			s.server.cfg.StreamOutboundBytes = 8192
		}
		wire := bytes.Repeat([]byte{0x33}, 65528)
		wire = wire[:4103]
		released := make(chan struct{})
		sent := make(chan error, 1)
		go func() {
			_, err := st.WriteOwnedFrame(wire, func(b []byte) {
				if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
					t.Error("not cleared")
				}
				close(released)
			})
			sent <- err
		}()
		if !reject {
			end := time.Now().Add(time.Second)
			for {
				s.mu.Lock()
				n := len(s.out)
				s.mu.Unlock()
				if n > 0 {
					break
				}
				if time.Now().After(end) {
					t.Fatal("not queued")
				}
				time.Sleep(time.Millisecond)
			}
			s.fail(context.Canceled)
			go s.writeLoop()
			<-s.writerDone
		}
		if err := <-sent; err == nil {
			t.Fatal("expected rejection/cancellation")
		}
		select {
		case <-released:
		case <-time.After(time.Second):
			t.Fatal("release missing")
		}
		s.mu.Lock()
		n := s.outBytes
		s.mu.Unlock()
		if n != 0 {
			t.Fatal("budget leak")
		}
	}
}
