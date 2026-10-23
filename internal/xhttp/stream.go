package xhttp

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// Stream is an unauthenticated transport byte stream. Only the core's complete
// VLESS decoder may authorize destinations. It is not a TCP half-close facade.
type Stream struct {
	session  *session
	writer   *responseWriter
	rMu, wMu sync.Mutex
}

func (st *Stream) Context() context.Context { return st.session.ctx }
func (st *Stream) Mode() string {
	st.session.mu.Lock()
	defer st.session.mu.Unlock()
	return st.session.mode
}
func (st *Stream) Read(b []byte) (int, error) {
	st.rMu.Lock()
	defer st.rMu.Unlock()
	return st.session.Read(b)
}
func (st *Stream) Write(b []byte) (int, error) {
	st.wMu.Lock()
	defer st.wMu.Unlock()
	return st.writer.Write(b)
}
func (st *Stream) Close() error      { st.session.close(ErrClosed); return nil }
func (st *Stream) CloseWrite() error { return ErrHalfCloseUnsupported }
func (st *Stream) Flush() error {
	st.wMu.Lock()
	defer st.wMu.Unlock()
	return st.writer.controller.Flush()
}
func (st *Stream) SetReadDeadline(t time.Time) error {
	ss := st.session
	ss.bodyMu.Lock()
	defer ss.bodyMu.Unlock()
	ss.mu.Lock()
	ss.readDeadline = t
	ss.notify()
	ss.mu.Unlock()
	if ss.bodyAlive {
		return ss.bodyRC.SetReadDeadline(t)
	}
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.writer.mu.Lock()
	st.writer.deadline = t
	st.writer.mu.Unlock()
	return st.writer.controller.SetWriteDeadline(t)
}
func (st *Stream) SetDeadline(t time.Time) error {
	if e := st.SetReadDeadline(t); e != nil {
		return e
	}
	return st.SetWriteDeadline(t)
}

type responseWriter struct {
	w          io.Writer
	controller *http.ResponseController
	session    *session
	timeout    time.Duration
	mu         sync.Mutex
	deadline   time.Time
}

func (w *responseWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if w.session.ctx.Err() != nil {
			return total, context.Cause(w.session.ctx)
		}
		n := min(len(p), 16384)
		w.mu.Lock()
		deadline := time.Now().Add(w.timeout)
		if !w.deadline.IsZero() && w.deadline.Before(deadline) {
			deadline = w.deadline
		}
		w.mu.Unlock()
		if e := w.controller.SetWriteDeadline(deadline); e != nil {
			return total, e
		}
		sent, e := w.w.Write(p[:n])
		total += sent
		if e == nil && sent != n {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = w.controller.Flush()
		}
		if e != nil {
			w.session.close(e)
			return total, e
		}
		w.session.mu.Lock()
		w.session.last = time.Now()
		w.session.mu.Unlock()
		p = p[n:]
	}
	return total, nil
}
