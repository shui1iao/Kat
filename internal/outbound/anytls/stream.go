package anytls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// Received-but-unread bytes buffered per stream. Beyond it the session
	// reader stops reading the TLS connection until the application reads:
	// plain TCP backpressure on the stream's own (exclusive) session.
	maxStreamBuffer = 512 << 10
	writeChunk      = 32 << 10
)

var errClosedByPeer = errors.New("anytls: stream closed by server")

// stream is one logical AnyTLS stream; it is the net.Conn returned by DialTCP.
// FIN closes the whole logical stream in both directions (the protocol has no
// half-close), so no CloseWrite is offered. Deadlines apply to this stream only.
type stream struct {
	s      *session
	id     uint32
	sentAt int64

	rmu, wmu sync.Mutex // serialize Read / Write callers

	mu       sync.Mutex
	in       [][]byte
	off      int
	inBytes  int
	rerr     error // terminal read state (io.EOF after FIN, or failure)
	werr     error // terminal write state
	acked    bool
	synErr   error
	closed   bool // local Close
	detached bool // removed from the session, slot released

	rch     chan struct{} // capacity 1: data/state for readers and await
	space   chan struct{} // capacity 1: buffer drained
	closing chan struct{} // closed by local Close

	rd, wd deadline
}

func newStream(s *session, id uint32) *stream {
	st := &stream{s: s, id: id, rch: make(chan struct{}, 1), space: make(chan struct{}, 1), closing: make(chan struct{})}
	st.rd.init()
	st.wd.init()
	return st
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// await waits for the server's verdict on a new stream. TCP needs the v2
// SYNACK; UoT only needs proof the session is authenticated (server settings),
// because servers may delay SYNACK until the UoT request arrives.
func (st *stream) await(ctx context.Context, needAck bool) error {
	s := st.s
	ver := s.ver
	for {
		st.mu.Lock()
		acked, synErr, rerr := st.acked, st.synErr, st.rerr
		st.mu.Unlock()
		if synErr != nil {
			return synErr
		}
		if acked {
			// Accepted; data already delivered stays readable even if the
			// session failed right after.
			return nil
		}
		if rerr != nil && rerr != io.EOF {
			return rerr
		}
		if rerr == io.EOF {
			return errClosedByPeer
		}
		if v, known := s.version(); known && (!needAck || v < 2) {
			return nil
		}
		if needAck {
			if _, known := s.version(); known {
				ver = nil // keep waiting for SYNACK only
			}
		}
		select {
		case <-st.rch:
		case <-ver:
		case <-ctx.Done():
			// Nothing at all came back since this stream was sent: treat the
			// session as dead so it is not reused.
			if s.lastRecv.Load() < st.sentAt {
				s.fail(errNoResponse)
			}
			return fmt.Errorf("anytls: waiting for server: %w", ctx.Err())
		}
	}
}

func (st *stream) acknowledge(msg []byte) {
	st.mu.Lock()
	if len(msg) == 0 {
		st.acked = true
		st.mu.Unlock()
		signal(st.rch)
		return
	}
	st.synErr = fmt.Errorf("anytls: server refused stream: %s", printable(msg))
	if st.rerr == nil {
		st.rerr = st.synErr
	}
	if st.werr == nil {
		st.werr = st.synErr
	}
	st.mu.Unlock()
	signal(st.rch)
	st.detach(false)
}

// push hands received data to the reader. When the buffer is full the session
// reader waits for the application (or stream close / session failure); the
// session is exclusive to this stream, so no other stream is held up and
// memory stays bounded by maxStreamBuffer plus one frame.
func (st *stream) push(b []byte) {
	for {
		st.mu.Lock()
		if st.closed || st.rerr != nil {
			st.mu.Unlock()
			return
		}
		if st.inBytes == 0 || st.inBytes+len(b) <= maxStreamBuffer {
			st.in = append(st.in, b)
			st.inBytes += len(b)
			st.mu.Unlock()
			signal(st.rch)
			return
		}
		st.mu.Unlock()
		select {
		case <-st.space:
		case <-st.s.done:
			return
		}
	}
}

// remoteClose handles the server's FIN: buffered data stays readable, then EOF.
func (st *stream) remoteClose(err error) {
	st.mu.Lock()
	if st.rerr == nil {
		st.rerr = err
	}
	if st.werr == nil {
		st.werr = errClosedByPeer
	}
	st.mu.Unlock()
	signal(st.rch)
	st.detach(false)
}

// abort is session failure: every operation errors (after buffered data).
func (st *stream) abort(err error) {
	st.mu.Lock()
	if st.rerr == nil || st.rerr == io.EOF {
		st.rerr = err
	}
	if st.werr == nil || st.werr == errClosedByPeer {
		st.werr = err
	}
	st.mu.Unlock()
	signal(st.rch)
	st.detach(false)
}

// detach removes the stream from its session once, optionally sending FIN,
// and returns its pool slot.
func (st *stream) detach(sendFIN bool) {
	st.mu.Lock()
	if st.detached {
		st.mu.Unlock()
		return
	}
	st.detached = true
	st.mu.Unlock()
	s := st.s
	s.detachStream(st.id)
	if sendFIN {
		_ = s.enqueue(&writeReq{wire: appendFrame(nil, cmdFIN, st.id, nil), done: make(chan error, 1)})
	}
	s.o.release(s)
}

func (st *stream) Read(p []byte) (int, error) {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return 0, net.ErrClosed
		}
		if st.rd.expired() {
			st.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(st.in) > 0 {
			if len(p) == 0 {
				st.mu.Unlock()
				return 0, nil
			}
			b := st.in[0]
			n := copy(p, b[st.off:])
			st.off += n
			if st.off == len(b) {
				st.in[0] = nil
				st.in = st.in[1:]
				st.off = 0
				st.inBytes -= len(b)
				signal(st.space)
			}
			st.mu.Unlock()
			return n, nil
		}
		if st.rerr != nil {
			e := st.rerr
			st.mu.Unlock()
			return 0, e
		}
		st.mu.Unlock()
		if len(p) == 0 {
			return 0, nil
		}
		select {
		case <-st.rch:
		case <-st.rd.done():
		case <-st.closing:
		}
	}
}

func (st *stream) Write(p []byte) (int, error) {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), writeChunk)
		if e := st.writeData(p[:n]); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	if total == 0 {
		if e := st.writeState(); e != nil {
			return 0, e
		}
	}
	return total, nil
}

func (st *stream) writeState() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return net.ErrClosed
	}
	if st.werr != nil {
		return st.werr
	}
	if st.wd.expired() {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// writeData sends data as PSH frames in one writer request: either all of it
// reaches the writer or (on deadline/close before pickup) none of it does.
func (st *stream) writeData(data []byte) error {
	if e := st.writeState(); e != nil {
		return e
	}
	s := st.s
	wire := make([]byte, 0, len(data)+headerSize*(len(data)/maxFrame+1))
	for len(data) > 0 {
		n := min(len(data), maxFrame)
		wire = appendFrame(wire, cmdPSH, st.id, data[:n])
		data = data[n:]
	}
	req := &writeReq{wire: wire, done: make(chan error, 1)}
	if e := s.enqueue(req); e != nil {
		return e
	}
	var stop error
	select {
	case e := <-req.done:
		return e
	case <-s.done:
		return s.cause()
	case <-st.wd.done():
		stop = os.ErrDeadlineExceeded
	case <-st.closing:
		stop = net.ErrClosed
	}
	if s.cancel(req) {
		return stop
	}
	// Already on the wire path: report the real outcome.
	select {
	case e := <-req.done:
		return e
	case <-s.done:
		return s.cause()
	}
}

// Close closes the logical stream (FIN) and never the shared session.
func (st *stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	st.in = nil
	st.inBytes = 0
	close(st.closing)
	st.mu.Unlock()
	signal(st.space)
	st.rd.stop()
	st.wd.stop()
	st.detach(true)
	return nil
}

func (st *stream) LocalAddr() net.Addr  { return st.s.conn.LocalAddr() }
func (st *stream) RemoteAddr() net.Addr { return st.s.conn.RemoteAddr() }
func (st *stream) SetDeadline(t time.Time) error {
	st.rd.set(t)
	st.wd.set(t)
	return nil
}
func (st *stream) SetReadDeadline(t time.Time) error  { st.rd.set(t); return nil }
func (st *stream) SetWriteDeadline(t time.Time) error { st.wd.set(t); return nil }

var _ net.Conn = (*stream)(nil)

// deadline is a resettable timer-backed channel closed when the deadline passes.
type deadline struct {
	mu      sync.Mutex
	ch      chan struct{}
	timer   *time.Timer
	gen     uint64
	isEnded bool
}

func (d *deadline) init() { d.ch = make(chan struct{}) }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gen++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.isEnded {
		d.ch = make(chan struct{})
		d.isEnded = false
	}
	if t.IsZero() {
		return
	}
	wait := time.Until(t)
	if wait <= 0 {
		close(d.ch)
		d.isEnded = true
		return
	}
	gen := d.gen
	d.timer = time.AfterFunc(wait, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.gen == gen && !d.isEnded {
			close(d.ch)
			d.isEnded = true
		}
	})
}

func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gen++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

func (d *deadline) done() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch
}

func (d *deadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isEnded
}
