package anytls

import (
	"context"
	"io"
	"os"
	"time"
)

// WriteTCPTo is the explicit TCP-upload entry point. It writes each already
// authenticated PSH remainder immediately, without a relay-sized copy/split.
// Ordinary Read/Write and UoT are unchanged. rMu serializes logical readers;
// neither Close nor session cancellation waits for it. The session mutex is
// NEVER held across target I/O. The relay must close its target on cancellation.
func (st *Stream) WriteTCPTo(w io.Writer) (int64, error) {
	st.rMu.Lock()
	defer st.rMu.Unlock()
	s := st.session
	var total int64
	for {
		s.mu.Lock()
		if s.ctx.Err() != nil && !st.closed {
			s.mu.Unlock()
			return total, context.Cause(s.ctx)
		}
		if len(st.input) > 0 {
			frame := st.input[0]
			offset := st.readOffset
			// Detach the sole owning reference before unlocking. Close/FIN may discard
			// queued input while this frame remains in-flight, fully charged until the
			// target write has actually returned and the entire allocation is cleared.
			st.input[0] = nil
			st.input = st.input[1:]
			st.readOffset = 0
			s.mu.Unlock()
			n, err := w.Write(frame[offset:])
			if n < 0 || n > len(frame)-offset {
				n, err = 0, io.ErrShortWrite
			}
			if err == nil && n != len(frame)-offset {
				err = io.ErrShortWrite
			}
			total += int64(n)
			s.mu.Lock()
			cost := len(frame) + 7
			releaseInboundFrame(frame)
			st.inBytes -= cost
			s.inBytes -= cost
			st.inFrames--
			s.inFrames--
			s.notify()
			s.mu.Unlock()
			if err != nil {
				return total, err
			}
			continue
		}
		if st.closed {
			err := st.err
			if err == nil {
				err = ErrStreamClosed
			}
			s.mu.Unlock()
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		deadline := st.readDeadline
		ch := s.waitReadChange()
		s.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !deadline.After(time.Now()) {
				return total, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-ch:
		case <-st.ctx.Done():
		case <-timeout:
			if timer != nil {
				timer.Stop()
			}
			return total, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
