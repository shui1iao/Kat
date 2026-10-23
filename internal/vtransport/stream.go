package vtransport

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// Stream is a bounded transport byte stream, not a VLESS-authenticated stream.
// Read/Write are independent; no plaintext or raw socket escape hatch is exposed.
type Stream struct {
	life     sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	r        io.Reader
	w        io.Writer
	closer   func() error
	rd, wd   func(time.Time) error
	half     func() error
	flush    func() error
	once     sync.Once
	err      error
	rMu, wMu sync.Mutex
}

func (st *Stream) Context() context.Context { return st.ctx }
func (st *Stream) Read(p []byte) (int, error) {
	st.rMu.Lock()
	defer st.rMu.Unlock()
	return st.r.Read(p)
}
func (st *Stream) Write(p []byte) (int, error) {
	st.wMu.Lock()
	defer st.wMu.Unlock()
	if st.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return st.w.Write(p)
}
func (st *Stream) Close() error {
	st.once.Do(func() {
		st.life.Lock()
		defer st.life.Unlock()
		st.cancel()
		if st.closer != nil {
			st.err = st.closer()
		}
	})
	return st.err
}
func (st *Stream) CloseWrite() error {
	if st.half == nil {
		return ErrHalfCloseUnsupported
	}
	st.wMu.Lock()
	defer st.wMu.Unlock()
	return st.half()
}
func (st *Stream) Flush() error {
	st.wMu.Lock()
	defer st.wMu.Unlock()
	if st.flush != nil {
		return st.flush()
	}
	return nil
}
func (st *Stream) SetReadDeadline(t time.Time) error {
	if st.rd == nil {
		return ErrDeadlineUnsupported
	}
	return st.rd(t)
}
func (st *Stream) SetWriteDeadline(t time.Time) error {
	if st.wd == nil {
		return ErrDeadlineUnsupported
	}
	return st.wd(t)
}
func (st *Stream) SetDeadline(t time.Time) error {
	if e := st.SetReadDeadline(t); e != nil {
		return e
	}
	return st.SetWriteDeadline(t)
}

func (st *Stream) install(r io.Reader, w io.Writer, closer func() error, rd, wd func(time.Time) error, half func() error) bool {
	st.life.Lock()
	defer st.life.Unlock()
	if st.ctx.Err() != nil {
		closer()
		return false
	}
	st.r = r
	st.w = w
	st.closer = closer
	st.rd = rd
	st.wd = wd
	st.half = half
	return true
}
