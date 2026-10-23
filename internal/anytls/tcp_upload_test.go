package anytls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type tcpUploadTransport struct {
	once   sync.Once
	closed chan struct{}
}

func (t *tcpUploadTransport) Read(p []byte) (int, error)  { <-t.closed; return 0, io.EOF }
func (t *tcpUploadTransport) Write(p []byte) (int, error) { return len(p), nil }
func (t *tcpUploadTransport) Close() error                { t.once.Do(func() { close(t.closed) }); return nil }

type tcpUploadHeldWriter struct {
	entered chan []byte
	release chan struct{}
}

func (w *tcpUploadHeldWriter) Write(p []byte) (int, error) {
	w.entered <- p
	<-w.release
	return 0, io.ErrClosedPipe
}

func tcpUploadStream(t *testing.T, payload []byte) (*session, *Stream, []byte) {
	t.Helper()
	srv, err := NewServer(cfg())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &session{server: srv, ctx: ctx, cancel: cancel, transport: &tcpUploadTransport{closed: make(chan struct{})}, change: make(chan struct{}), active: map[uint32]*Stream{}, closed: map[uint32]bool{}}
	stctx, stcancel := context.WithCancelCause(ctx)
	st := &Stream{session: s, id: 1, ctx: stctx, cancel: stcancel}
	s.active[1] = st
	var b []byte
	if len(payload) > 0 {
		b = append([]byte(nil), payload...)
		b = b[:len(b):len(b)]
		st.input = [][]byte{b}
		st.inFrames = 1
		st.inBytes = len(b) + 7
		s.inFrames = 1
		s.inBytes = st.inBytes
	}
	t.Cleanup(func() { s.fail(context.Canceled) })
	return s, st, b
}
func TestTCPUploadInFlightChargedAcrossClose(t *testing.T) {
	for _, mode := range []string{"local-close", "peer-fin", "session-close", "parent-cancel"} {
		t.Run(mode, func(t *testing.T) {
			plain := bytes.Repeat([]byte{0x47}, 65535)
			s, st, frame := tcpUploadStream(t, plain)
			st.readOffset = 7
			queued := bytes.Repeat([]byte{0x62}, 32)
			st.input = append(st.input, queued)
			st.inFrames++
			s.inFrames++
			st.inBytes += 39
			s.inBytes += 39
			w := &tcpUploadHeldWriter{entered: make(chan []byte, 1), release: make(chan struct{})}
			done := make(chan error, 1)
			go func() { _, err := st.WriteTCPTo(w); done <- err }()
			data := <-w.entered
			if !bytes.Equal(data, plain[7:]) {
				close(w.release)
				<-done
				t.Fatal("readOffset/payload mismatch")
			}
			// A separate stream's Read must run while the target Write is blocked.
			otherCtx, otherCancel := context.WithCancelCause(s.ctx)
			defer otherCancel(context.Canceled)
			other := &Stream{session: s, id: 2, ctx: otherCtx, cancel: otherCancel, input: [][]byte{[]byte("abc")}, inFrames: 1, inBytes: 10}
			s.mu.Lock()
			s.active[2] = other
			s.inFrames++
			s.inBytes += 10
			s.mu.Unlock()
			read := make(chan error, 1)
			go func() {
				p := make([]byte, 3)
				n, e := other.Read(p)
				if n != 3 || string(p) != "abc" {
					e = io.ErrUnexpectedEOF
				}
				read <- e
			}()
			select {
			case e := <-read:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(time.Second):
				close(w.release)
				<-done
				t.Fatal("session mutex held across target.Write")
			}
			closed := make(chan struct{})
			go func() {
				switch mode {
				case "local-close":
					// Skip only the irrelevant FIN writer: cancellation causes send to return
					// immediately; real FIN transport/relay behavior is covered by kernel tests.
					s.fail(context.Canceled)
					st.Close()
				case "peer-fin":
					s.mu.Lock()
					st.closeLocked(io.EOF, true, false)
					s.mu.Unlock()
				case "session-close":
					s.fail(io.EOF)
					s.mu.Lock()
					st.closeLocked(io.EOF, false, true)
					s.mu.Unlock()
				case "parent-cancel":
					s.fail(context.Canceled)
				}
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(time.Second):
				close(w.release)
				<-done
				t.Fatal("Close/FIN blocked on target I/O")
			}
			// Close must not clear the detached frame or remove its budget reservation.
			s.mu.Lock()
			charged := st.inBytes
			frames := st.inFrames
			s.mu.Unlock()
			intact := bytes.Equal(frame, plain)
			if charged < len(frame)+7 || frames < 1 || !intact {
				t.Error("in-flight frame uncharged/cleared before write completion", charged, frames)
			}
			close(w.release)
			if e := <-done; !errors.Is(e, io.ErrClosedPipe) {
				t.Error(e)
			}
			s.mu.Lock()
			st.closeLocked(ErrStreamClosed, false, true)
			remaining := st.inBytes
			sf := st.inFrames
			all := s.inBytes
			s.mu.Unlock()
			if remaining != 0 || sf != 0 || all != 0 || !bytes.Equal(frame, make([]byte, len(frame))) {
				t.Fatal("accounting/zeroization leak", remaining, sf, all)
			}
		})
	}
}

type tcpUploadChunks struct {
	bytes.Buffer
	sizes []int
	short bool
	err   error
}

func (w *tcpUploadChunks) Write(p []byte) (int, error) {
	w.sizes = append(w.sizes, len(p))
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return len(p) - 1, nil
	}
	return w.Buffer.Write(p)
}
func TestTCPUploadWholeFramesPartialReadAndErrors(t *testing.T) {
	payload := bytes.Repeat([]byte{0x44}, 65535)
	for _, w := range []*tcpUploadChunks{{}, {short: true}, {err: io.ErrClosedPipe}} {
		s, st, b := tcpUploadStream(t, payload)
		st.readOffset = 9
		s.mu.Lock()
		st.closeLocked(io.EOF, true, false)
		s.mu.Unlock()
		n, e := st.WriteTCPTo(w)
		if w.short {
			if e != io.ErrShortWrite || n != int64(len(payload)-10) {
				t.Fatal(n, e)
			}
		} else if w.err != nil {
			if e != w.err || n != 0 {
				t.Fatal(n, e)
			}
		} else if e != nil || n != int64(len(payload)-9) || !bytes.Equal(w.Bytes(), payload[9:]) {
			t.Fatal(n, e)
		}
		if len(w.sizes) != 1 || w.sizes[0] != len(payload)-9 || !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("frame split or not cleared", w.sizes)
		}
	}
}
func TestTCPUploadDeadlineAndEmptyCancellation(t *testing.T) {
	_, st, _ := tcpUploadStream(t, nil)
	st.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e := st.WriteTCPTo(io.Discard); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	s, st, _ := tcpUploadStream(t, nil)
	done := make(chan error, 1)
	go func() { _, e := st.WriteTCPTo(io.Discard); done <- e }()
	s.fail(context.Canceled)
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("empty wait did not cancel")
	}
}
