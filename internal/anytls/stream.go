package anytls

import (
	"context"
	"io"
	"os"
	"sync"
	"time"
)

// Stream supports independent read/write deadlines, but deliberately does not
// pretend FIN is TCP half-close. It is io.ReadWriteCloser, not net.Conn.
type Stream struct {
	readOffset                                                            int
	session                                                               *session
	id                                                                    uint32
	ctx                                                                   context.Context
	cancel                                                                context.CancelCauseFunc
	rMu, wMu                                                              sync.Mutex
	input                                                                 [][]byte
	inFrames, inBytes, reservedFrames, reservedBytes, outFrames, outBytes int
	closed, remote                                                        bool
	err                                                                   error
	readDeadline, writeDeadline                                           time.Time
}

func (st *Stream) ID() uint32               { return st.id }
func (st *Stream) Context() context.Context { return st.ctx }
func (st *Stream) SessionStats() SessionStats {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionStats{len(s.active), len(s.workers), s.inFrames, s.inBytes, s.outFrames, s.outBytes, s.version}
}
func (st *Stream) SetReadDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	st.readDeadline = t
	s.notifyRead()
	s.mu.Unlock()
	return nil
}
func (st *Stream) SetWriteDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	st.writeDeadline = t
	s.notify()
	s.mu.Unlock()
	return nil
}
func (st *Stream) SetDeadline(t time.Time) error {
	_ = st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.rMu.Lock()
	defer st.rMu.Unlock()
	s := st.session
	for {
		s.mu.Lock()
		if s.ctx.Err() != nil && !st.closed {
			s.mu.Unlock()
			return 0, context.Cause(s.ctx)
		}
		if len(st.input) > 0 {
			b := st.input[0]
			n := copy(p, b[st.readOffset:])
			st.readOffset += n
			// Charge the entire retained allocation until the frame is freed.
			if st.readOffset == len(b) {
				cost := len(b) + 7
				// Detach the owner field before the backing array is cached;
				// accounting remains full until clear/return has completed.
				st.input[0] = nil
				st.input = st.input[1:]
				st.readOffset = 0
				releaseInboundFrame(b)
				st.inBytes -= cost
				s.inBytes -= cost
				st.inFrames--
				s.inFrames--
			}

			s.notify()
			s.mu.Unlock()
			return n, nil
		}
		if st.closed {
			err := st.err
			if err == nil {
				err = ErrStreamClosed
			}
			s.mu.Unlock()
			return 0, err
		}
		deadline := st.readDeadline
		ch := s.waitReadChange()
		s.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !deadline.After(time.Now()) {
				return 0, os.ErrDeadlineExceeded
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
			return 0, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
func (st *Stream) Write(p []byte) (int, error) {
	st.wMu.Lock()
	defer st.wMu.Unlock()
	s := st.session
	total := 0
	for len(p) > 0 {
		n := min(len(p), s.server.cfg.MaxFrameData)
		s.mu.Lock()
		deadline := st.writeDeadline
		s.mu.Unlock()
		if e := s.send(cmdPSH, st.id, p[:n], st, deadline); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// WriteOwnedFrame is the TCP-down relay's single-PSH ownership transfer.
// wire reserves seven header bytes followed by payload, with no aliases retained
// by the caller. The whole capacity is charged before enqueue. It is cleared
// before release is called exactly once, even on rejection/cancellation; release
// must be nonblocking and must not call back into the session. A timed-out call
// does NOT return ownership: the writer still owns it through transport I/O.
// Ordinary Write (including UoT) and the receive path are unchanged.
func (st *Stream) WriteOwnedFrame(wire []byte, release func([]byte)) (int, error) {
	if len(wire) < 7 || len(wire)-7 > st.session.server.cfg.MaxFrameData {
		disposeOutboundWire(wire, release)
		return 0, ErrQueueLimit
	}
	if len(wire) == 7 {
		disposeOutboundWire(wire, release)
		return 0, nil
	}
	st.wMu.Lock()
	defer st.wMu.Unlock()
	s := st.session
	s.mu.Lock()
	deadline := st.writeDeadline
	s.mu.Unlock()
	n := len(wire) - 7
	if err := s.send(cmdPSH, st.id, wire[7:], st, deadline, outboundLease{wire, release}); err != nil {
		return 0, err
	}
	return n, nil
}

func (st *Stream) clearInputLocked() {
	s := st.session
	queued := st.input
	st.input = nil
	st.readOffset = 0
	for i, b := range queued {
		cost := len(b) + 7
		queued[i] = nil
		releaseInboundFrame(b)
		st.inBytes -= cost
		s.inBytes -= cost
		st.inFrames--
		s.inFrames--
	}
}
func (st *Stream) closeLocked(err error, remote, discard bool) {
	defer st.session.notifyRead()
	if discard {
		st.clearInputLocked()
	}
	if st.closed {
		return
	}
	st.closed = true
	st.remote = remote
	st.err = err
	delete(st.session.active, st.id)
	st.session.remember(st.id)
	st.cancel(ErrStreamClosed)
	st.session.notify()
}

// Close sends one FIN only for a locally initiated stream close. A peer FIN is
// never echoed. Closing a stream never closes its reusable session.
func (st *Stream) Close() error {
	s := st.session
	s.mu.Lock()
	already := st.closed
	st.closeLocked(ErrStreamClosed, false, true)
	s.mu.Unlock()
	if already || s.ctx.Err() != nil {
		return nil
	}
	return s.send(cmdFIN, st.id, nil, nil, time.Time{})
}

// CloseWrite has no wire-equivalent: AnyTLS FIN closes a whole logical stream.
// Returning this sentinel changes neither read nor write state.
func (st *Stream) CloseWrite() error { return ErrHalfCloseUnsupported }

// Ping uses the v2 heartbeat. A timed-out ping aborts the entire session rather
// than leaving an indefinitely stalled connection and its streams allocated.
func (st *Stream) Ping(ctx context.Context) error {
	s := st.session
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	s.mu.Lock()
	if s.version < 2 {
		s.mu.Unlock()
		return ErrProtocol
	}
	ack := make(chan struct{})
	s.pingAck = ack
	s.mu.Unlock()
	if e := s.send(cmdHeartRequest, 0, nil, nil, time.Time{}); e != nil {
		return e
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		s.fail(context.Cause(ctx))
		return context.Cause(ctx)
	case <-s.ctx.Done():
		return context.Cause(s.ctx)
	}
}

var _ io.ReadWriteCloser = (*Stream)(nil)
