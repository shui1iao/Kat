package anytls

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func inboundFixture(t *testing.T) (*session, *Stream) {
	t.Helper()
	srv, e := NewServer(cfg())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(context.Canceled) })
	s := &session{server: srv, ctx: ctx, cancel: cancel, change: make(chan struct{}), active: make(map[uint32]*Stream), closed: make(map[uint32]bool)}
	child, stop := context.WithCancelCause(ctx)
	st := &Stream{session: s, id: 1, ctx: child, cancel: stop}
	s.active[1] = st
	return s, st
}
func TestInboundPoolExactCapClearAndBound(t *testing.T) {
	var owned [][]byte
	for i := 0; i < 40; i++ {
		p := takeInboundFrame(65535)
		if len(p) != 65535 || cap(p) != 65535 {
			t.Fatal("wrong allocation capacity")
		}
		for j := range p {
			p[j] = 0x6a
		}
		owned = append(owned, p)
	}
	for _, p := range owned {
		releaseInboundFrame(p)
	}
	inboundBuffers.Lock()
	if len(inboundBuffers.frames) > 16 || inboundBuffers.bytes > 512*1024 {
		t.Fatal("cache unbounded")
	}
	inboundBuffers.Unlock()
	p := takeInboundFrame(17)
	if cap(p) != 17 {
		t.Fatal("small frame borrowed large backing")
	}
	releaseInboundFrame(p)
	q := takeInboundFrame(65535)
	if !bytes.Equal(q, make([]byte, len(q))) {
		t.Fatal("prior owner's data retained")
	}
	releaseInboundFrame(q)
}
func TestInboundFramePartialReadChargeCloseAndRemoteFIN(t *testing.T) {
	for _, remote := range []bool{false, true} {
		s, st := inboundFixture(t)
		if e := s.reserveInbound(st, 4096); e != nil {
			t.Fatal(e)
		}
		p := takeInboundFrame(4096)
		for i := range p {
			p[i] = 0x77
		}
		s.publishInbound(st, p, nil)
		first := make([]byte, 17)
		if n, e := st.Read(first); e != nil || n != 17 {
			t.Fatal(n, e)
		}
		s.mu.Lock()
		if st.inBytes != 4103 || s.inBytes != 4103 || st.inFrames != 1 {
			t.Fatal("partial read undercharged backing allocation")
		}
		st.closeLocked(io.EOF, remote, !remote)
		if remote && s.inBytes != 4103 {
			t.Fatal("remote FIN prematurely released buffered data")
		}
		s.mu.Unlock()
		if remote {
			rest, e := io.ReadAll(st)
			if e != nil || !bytes.Equal(append(first, rest...), bytes.Repeat([]byte{0x77}, 4096)) {
				t.Fatal("remote FIN lost tail", e)
			}
		}
		s.mu.Lock()
		if s.inBytes != 0 || st.inBytes != 0 || s.inFrames != 0 {
			t.Fatal("allocation not released")
		}
		s.mu.Unlock()
		if !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("backing not cleared")
		}
	}
}
func TestInboundReservationSurvivesCloseUntilPublish(t *testing.T) {
	for _, readErr := range []error{nil, io.ErrUnexpectedEOF} {
		s, st := inboundFixture(t)
		if e := s.reserveInbound(st, 32768); e != nil {
			t.Fatal(e)
		}
		p := takeInboundFrame(32768)
		for i := range p {
			p[i] = 0x5b
		}
		s.mu.Lock()
		st.closeLocked(ErrStreamClosed, false, true)
		if s.inBytes != 32775 || st.reservedBytes != 32775 || st.reservedFrames != 1 {
			t.Fatal("closed inflight allocation was not charged")
		}
		s.mu.Unlock()
		s.publishInbound(st, p, readErr)
		s.mu.Lock()
		if s.inBytes != 0 || s.inFrames != 0 || st.reservedBytes != 0 || st.reservedFrames != 0 || len(st.input) != 0 {
			t.Fatal("late/truncated body leaked or republished")
		}
		s.mu.Unlock()
		if !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("late/truncated buffer not cleared")
		}
	}
}
