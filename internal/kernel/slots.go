package kernel

import (
	"context"
	"sync"
)

// slots is a counting budget whose limit can change at run time (reload).
// A lower limit never revokes slots already held: holders keep them until
// they release, and new acquisitions fail until usage drops below the limit.
type slots struct {
	mu    sync.Mutex
	used  int
	max   int
	freed chan struct{} // closed (and replaced lazily) whenever a slot is released
}

func newSlots(max int) *slots { return &slots{max: max} }

// try takes one slot without waiting.
func (s *slots) try() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used >= s.max {
		return false
	}
	s.used++
	return true
}

// acquire waits for one slot until ctx ends.
func (s *slots) acquire(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.used < s.max {
			s.used++
			s.mu.Unlock()
			return nil
		}
		if s.freed == nil {
			s.freed = make(chan struct{})
		}
		wait := s.freed
		s.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// release returns one slot.
func (s *slots) release() {
	s.mu.Lock()
	s.used--
	if s.freed != nil {
		close(s.freed)
		s.freed = nil
	}
	s.mu.Unlock()
}

// setLimit changes the limit for future acquisitions.
func (s *slots) setLimit(n int) {
	s.mu.Lock()
	s.max = n
	if s.freed != nil {
		close(s.freed)
		s.freed = nil
	}
	s.mu.Unlock()
}

func (s *slots) limit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.max
}

func (s *slots) inUse() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}
