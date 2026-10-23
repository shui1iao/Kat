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

func (s *Server) copy(dst, src net.Conn) error {
	if t, ok := ss2022DownSource(src); ok {
		return s.copySS2022Down(dst, src, t)
	}
	if !s.cfg.Limits.DisableFastPath {
		if d, ok := dst.(*net.TCPConn); ok {
			if r, ok := src.(*net.TCPConn); ok {
				_, e := d.ReadFrom(r)
				return e
			}
		}
	}
	b := s.pool.get()
	defer s.pool.put(b)
	_, e := io.CopyBuffer(writeOnly{dst}, readOnly{src}, b)
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
	transfer := func(dst, src net.Conn) {
		e := s.copy(dst, src)
		if e == nil {
			e = closeWrite(dst)
		}
		done <- e
	}
	go transfer(a, b)
	go transfer(b, a)
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
