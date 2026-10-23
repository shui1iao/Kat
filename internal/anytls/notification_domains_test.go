package anytls

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestNotificationDomainsNoCrossWake(t *testing.T) {
	s, st := inboundFixture(t)
	s.mu.Lock()
	r1 := s.waitReadChange()
	r2 := s.waitReadChange()
	w := s.waitWriterChange()
	budget := s.waitChange()
	s.notifyWriter()
	s.mu.Unlock()
	select {
	case <-w:
	default:
		t.Fatal("writer missing wake")
	}
	select {
	case <-r1:
		t.Fatal("outbound progress woke reader")
	default:
	}
	select {
	case <-budget:
		t.Fatal("outbound enqueue woke unrelated budget waiter")
	default:
	}
	if r1 != r2 {
		t.Fatal("readers not sharing generation")
	}
	if e := s.reserveInbound(st, 4); e != nil {
		t.Fatal(e)
	}
	s.publishInbound(st, []byte("data"), nil)
	select {
	case <-r1:
	default:
		t.Fatal("input not published")
	}
	select {
	case <-r2:
	default:
		t.Fatal("second reader missed broadcast")
	}
	select {
	case <-w:
		t.Fatal("inbound publication woke empty writer")
	default:
	}
	select {
	case <-budget:
		t.Fatal("publication consumed, not freed, budget")
	default:
	}
	b := make([]byte, 4)
	if n, e := st.Read(b); e != nil || n != 4 {
		t.Fatal(n, e)
	}
	select {
	case <-budget:
	default:
		t.Fatal("cleared frame did not notify capacity waiter")
	}
	s.mu.Lock()
	r := s.waitReadChange()
	s.mu.Unlock()
	st.SetReadDeadline(time.Now().Add(time.Second))
	select {
	case <-r:
	default:
		t.Fatal("read deadline lost wake")
	}
	s.mu.Lock()
	r = s.waitReadChange()
	st.closeLocked(io.EOF, true, true)
	s.mu.Unlock()
	select {
	case <-r:
	default:
		t.Fatal("FIN lost reader wake")
	}
}
func TestNotificationWriterEdgesCoalesceAndCancel(t *testing.T) {
	s, _ := inboundFixture(t)
	s.mu.Lock()
	w := s.waitWriterChange()
	s.notifyWriter()
	s.notifyWriter()
	s.mu.Unlock()
	select {
	case <-w:
	default:
		t.Fatal("missing edge")
	}
	select {
	case <-w:
		t.Fatal("unbounded writer tokens")
	default:
	}
	s.mu.Lock()
	if s.waitWriterChange() != w {
		t.Error("writer channel reallocated per packet")
	}
	s.mu.Unlock()
	// Real read loops still select their stream child context; cancellation does
	// not rely on an unrelated progress broadcast.
	s2, st2 := inboundFixture(t)
	done := make(chan error, 1)
	go func() { _, e := st2.Read(make([]byte, 1)); done <- e }()
	s2.cancel(context.Canceled)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not wake receive domain")
	}
}
