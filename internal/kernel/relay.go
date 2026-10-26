package kernel

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type bufferPool struct {
	size int
	free chan []byte
}

func newBufferPool(size, count int) *bufferPool { return &bufferPool{size, make(chan []byte, count)} }
func (p *bufferPool) get() []byte {
	select {
	case b := <-p.free:
		return b
	default:
		return make([]byte, p.size)
	}
}
func (p *bufferPool) put(b []byte) {
	if cap(b) != p.size {
		return
	}
	clear(b[:cap(b)])
	select {
	case p.free <- b[:p.size]:
	default:
	}
}

type readOnly struct{ io.Reader }
type writeOnly struct{ io.Writer }

func (s *Server) copy(dst, src net.Conn) error { return s.copyM(dst, src, meter{}) }

// spliceChunk bounds one kernel splice while statistics are kept, so that
// counters and rates advance during long transfers.
const spliceChunk = 256 << 10

// copyM is copy with payload metering: m counts the bytes written to dst.
func (s *Server) copyM(dst, src net.Conn, m meter) error {
	if t, ok := ss2022DownSource(src); ok {
		return s.copySS2022DownM(dst, src, t, m)
	}
	if !s.cfg.Limits.DisableFastPath {
		if d, ok := dst.(*net.TCPConn); ok {
			if r, ok := src.(*net.TCPConn); ok {
				if m.f == nil {
					_, e := d.ReadFrom(r)
					return e
				}
				for {
					// LimitedReader over a TCPConn keeps the splice path.
					n, e := d.ReadFrom(&io.LimitedReader{R: r, N: spliceChunk})
					m.add(int(n))
					if e != nil || n < spliceChunk {
						return e
					}
				}
			}
		}
	}
	b := s.pool.get()
	defer s.pool.put(b)
	_, e := io.CopyBuffer(writeOnly{m.writer(dst)}, readOnly{src}, b)
	return e
}
func closeWrite(c net.Conn) error {
	if v, ok := c.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}

type activityStream struct {
	net.Conn
	last *atomic.Int64
}

func (c *activityStream) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) CloseWrite() error { return closeWrite(c.Conn) }
func (s *Server) relay(ctx context.Context, a, b net.Conn) error {
	return s.relayIdle(ctx, a, b, s.cfg.Limits.TCPIdle.value())
}
func (s *Server) relayIdle(ctx context.Context, a, b net.Conn, idle time.Duration) error {
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
						originalA.Close()
						originalB.Close()
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
	up, down := meters(ctx)
	transfer := func(dst, src net.Conn, m meter) {
		e := s.copyM(dst, src, m)
		if e == nil {
			e = closeWrite(dst)
		}
		done <- e
	}
	// a is the client side, b the target: b->a is download, a->b upload.
	go transfer(a, b, down)
	go transfer(b, a, up)
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		a.Close()
		b.Close()
		<-done
		<-done
		return ctx.Err()
	}
	if err != nil {
		a.Close()
		b.Close()
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
		a.Close()
		b.Close()
		<-done
		err = ctx.Err()
	}
	return err
}
