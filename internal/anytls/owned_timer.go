package anytls

import "time"

// This cache shares the already reserved16KiB owned metadata allowance:16
// descriptors/completion channels plus16 timer wrappers. No payload retention.
// A timer is reusable ONLY after Stop reports that its callback cannot execute.
// If Stop is false the timer is discarded; only the callback may clear owner.
// That preserves absolute queue+I/O timeout and prevents a stale callback from
// cancelling a subsequent session. Cache-full timers are simply GC eligible.
type ownedWriteTimer struct {
	timer *time.Timer
	owner *session
}

var ownedWriteTimers = make(chan *ownedWriteTimer, OwnedMetadataCacheSlots)

func acquireOwnedWriteTimer(s *session, end time.Time) *ownedWriteTimer {
	select {
	case w := <-ownedWriteTimers:
		w.owner = s
		w.timer.Reset(time.Until(end))
		return w
	default:
		w := &ownedWriteTimer{owner: s}
		w.timer = time.AfterFunc(time.Until(end), func() { owner := w.owner; owner.fail(ErrWriteTimeout); w.owner = nil })
		return w
	}
}
func stopOwnedWriteTimer(w *ownedWriteTimer) bool {
	if !w.timer.Stop() {
		return false
	}
	w.owner = nil
	select {
	case ownedWriteTimers <- w:
	default:
	}
	return true
}
