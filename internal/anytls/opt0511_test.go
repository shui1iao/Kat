package anytls

import (
	"bytes"
	"testing"
)

func TestInboundCacheAdaptsWithinSameBudget(t *testing.T) {
	inboundBuffers.Lock()
	inboundBuffers.frames = nil
	inboundBuffers.bytes = 0
	inboundBuffers.Unlock()
	for i := 1; i <= inboundCacheFrames; i++ {
		releaseInboundFrame(make([]byte, i))
	}
	p := make([]byte, 65535)
	for i := range p {
		p[i] = 0xa7
	}
	releaseInboundFrame(p)
	q := takeInboundFrame(len(p))
	if &p[0] != &q[0] {
		t.Fatal("cold small cache prevents returned hot allocation reuse")
	}
	if cap(q) != len(p) || !bytes.Equal(q, make([]byte, len(q))) {
		t.Fatal("capacity or clear changed")
	}
	releaseInboundFrame(q)
	inboundBuffers.Lock()
	defer inboundBuffers.Unlock()
	if len(inboundBuffers.frames) > inboundCacheFrames || inboundBuffers.bytes > inboundCacheBytes {
		t.Fatal("budget expanded")
	}
}
func TestLazyNotifyBroadcastNoLostWakeup(t *testing.T) {
	s := &session{}
	s.mu.Lock()
	s.notify()
	if s.change != nil {
		t.Fatal("notify with no waiters allocated")
	}
	first := s.waitChange()
	second := s.waitChange()
	if first != second {
		t.Fatal("waiters not sharing broadcast")
	}
	s.notify()
	select {
	case <-first:
	default:
		t.Fatal("waiter missed notification")
	}
	select {
	case <-second:
	default:
		t.Fatal("second waiter missed notification")
	}
	next := s.waitChange()
	select {
	case <-next:
		t.Fatal("new waiter inherited stale notification")
	default:
	}
	s.notify()
	s.mu.Unlock()
}
