package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type ss2022ReadActivity struct {
	io.Writer
	last *atomic.Int64
}

func (w ss2022ReadActivity) Write(p []byte) (int, error) {
	// Match the old source activity update after a successful plaintext read,
	// before the possibly blocking target write. The destination updates again.
	w.last.Store(time.Now().UnixNano())
	return w.Writer.Write(p)
}
func (s *Server) copySS2022Up(dst, src net.Conn) error {
	raw := src
	var writer io.Writer = dst
	if activity, ok := src.(*activityStream); ok {
		raw = activity.Conn
		writer = ss2022ReadActivity{dst, activity.last}
	}
	if stream, ok := raw.(*encryptedStream); ok {
		if codec, ok := stream.codec.(*ss.TCPConn); ok {
			_, err := codec.Write2022To(writer, s.pool.size)
			return err
		}
	}
	return s.copy(dst, src)
}

// SS2022-only relay. Preserve relayIdle's half-close/drain/idle behavior, but
// on forced shutdown close the target BEFORE the codec. Write2022To owns rMu
// while blocked in target.Write; codec.Close waits for that ownership before
// clearing resident plaintext. Closing the client first would deadlock before
// target.Close could unblock the writer. The shared relay remains unchanged.
func (s *Server) relaySS2022(ctx context.Context, a, b net.Conn) error {
	idle := s.cfg.Limits.TCPIdle.value()
	if idle > 0 {
		var last atomic.Int64
		last.Store(time.Now().UnixNano())
		stop := make(chan struct{})
		exited := make(chan struct{})
		defer func() { close(stop); <-exited }()
		originalA, originalB := a, b
		go func() {
			defer close(exited)
			timer := time.NewTimer(idle)
			defer timer.Stop()
			for {
				select {
				case <-stop:
					return
				case <-timer.C:
					remaining := idle - time.Since(time.Unix(0, last.Load()))
					if remaining <= 0 {
						originalB.Close()
						originalA.Close()
						return
					}
					timer.Reset(remaining)
				}
			}
		}()
		a = &activityStream{a, &last}
		b = &activityStream{b, &last}
	}

	done := make(chan error, 2)
	transfer := func(dst, src net.Conn, up bool) {
		var e error
		if up {
			e = s.copySS2022Up(dst, src)
		} else {
			e = s.copy(dst, src)
		}
		if e == nil {
			e = closeWrite(dst)
		}
		done <- e
	}
	go transfer(a, b, false)
	go transfer(b, a, true)
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		b.Close()
		a.Close()
		<-done
		<-done
		return ctx.Err()
	}
	if err != nil {
		b.Close()
		a.Close()
	} else {
		deadline := time.Now().Add(s.cfg.Limits.DrainTimeout.value())
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
	}
	select {
	case e := <-done:
		if err == nil {
			err = e
		}
	case <-ctx.Done():
		b.Close()
		a.Close()
		<-done
		err = ctx.Err()
	}
	return err
}
