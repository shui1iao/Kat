package xhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type limitedListener struct {
	net.Listener
	s *Server
}

func (l limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		l.s.mu.Lock()
		reject := l.s.stopped || len(l.s.conns) >= l.s.cfg.MaxConnections
		if !reject {
			l.s.conns[c] = true
		}
		l.s.mu.Unlock()
		if reject {
			c.Close()
			continue
		}
		c.SetDeadline(time.Now().Add(l.s.cfg.HeaderTimeout))
		return c, nil
	}
}
func (s *Server) releaseConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	one, single := s.listener.(*oneListener)
	empty := len(s.conns) == 0
	s.notify()
	s.mu.Unlock()
	if single && empty {
		one.Close()
	}
}

// Serve owns the caller-provided secure TLS listener. ALPN h2/http1.1 and trust
// are external. It never creates plaintext fallback, TLS config or target dials.
func (s *Server) Serve(ctx context.Context, l net.Listener, h Handler) error {
	if l == nil || h == nil {
		return ErrConfig
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrConfig
	}
	s.running = true
	s.listener = l
	s.ctx = ctx
	s.mu.Unlock()
	hs := &http.Server{ReadHeaderTimeout: s.cfg.HeaderTimeout, IdleTimeout: s.cfg.IdleTimeout, MaxHeaderBytes: s.cfg.MaxHeaderBytes, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handle(w, r, h) }), ConnState: func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			s.releaseConn(c)
		}
	}}
	if e := http2.ConfigureServer(hs, &http2.Server{MaxConcurrentStreams: uint32(s.cfg.MaxRequests), MaxReadFrameSize: 16384, MaxUploadBufferPerConnection: 1048576, MaxUploadBufferPerStream: 131072, IdleTimeout: s.cfg.IdleTimeout, WriteByteTimeout: s.cfg.IOTimeout}); e != nil {
		return e
	}
	s.mu.Lock()
	s.http = hs
	s.mu.Unlock()
	stop := make(chan struct{})
	go s.reap(stop)
	go func() {
		select {
		case <-ctx.Done():
			s.closeAll()
		case <-stop:
		}
	}()
	err := hs.Serve(limitedListener{l, s})
	close(stop)
	s.closeAll()
	timer := time.NewTimer(s.cfg.ShutdownTimeout)
	defer timer.Stop()
	for {
		s.mu.Lock()
		n := s.handlers + s.requests
		changed := s.changed
		s.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-changed:
		case <-timer.C:
			return ErrShutdownTimeout
		}
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (s *Server) closeAll() {
	s.mu.Lock()
	s.stopped = true
	l := s.listener
	hs := s.http
	var all []*session
	for _, ss := range s.sessions {
		all = append(all, ss)
	}
	var conns []net.Conn
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if l != nil {
		l.Close()
	}
	for _, ss := range all {
		ss.close(context.Canceled)
	}
	for _, c := range conns {
		c.Close()
	}
	if hs != nil {
		hs.Close()
	}
}
func (s *Server) reap(stop <-chan struct{}) {
	interval := s.cfg.PairTimeout / 4
	if interval > time.Second {
		interval = time.Second
	}
	if interval < 5*time.Millisecond {
		interval = 5 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.mu.Lock()
			s.expireRetired(now)
			var expired []*session
			for _, ss := range s.sessions {
				ss.mu.Lock()
				unpaired := !ss.down || !ss.up
				stale := now.Sub(ss.last) > s.cfg.IdleTimeout
				late := unpaired && now.Sub(ss.created) > s.cfg.PairTimeout
				ss.mu.Unlock()
				if stale || late {
					expired = append(expired, ss)
				}
			}
			s.mu.Unlock()
			for _, ss := range expired {
				ss.close(context.DeadlineExceeded)
			}
		case <-stop:
			return
		}
	}
}
func (s *Server) ServeConn(ctx context.Context, c net.Conn, h Handler) error {
	if c == nil {
		return ErrConfig
	}
	return s.Serve(ctx, &oneListener{c: c, closed: make(chan struct{})}, h)
}

type oneListener struct {
	mu     sync.Mutex
	c      net.Conn
	used   bool
	closed chan struct{}
	once   sync.Once
}

func (l *oneListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		c := l.c
		l.mu.Unlock()
		return c, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}
func (l *oneListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *oneListener) Addr() net.Addr { return l.c.LocalAddr() }
