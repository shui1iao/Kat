// Package vtransport provides bounded VLESS-compatible transport byte streams.
// It neither authenticates VLESS nor dials targets nor configures TLS trust.
package vtransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type Kind string

const (
	WebSocket   Kind = "ws"
	HTTPUpgrade Kind = "httpupgrade"
	GRPC        Kind = "grpc"
)

var (
	ErrConfig               = errors.New("vtransport: invalid configuration")
	ErrHalfCloseUnsupported = errors.New("vtransport: half-close unsupported")
	ErrDeadlineUnsupported  = errors.New("vtransport: deadline unsupported")
	ErrProtocol             = errors.New("vtransport: malformed transport message")
	ErrLimit                = errors.New("vtransport: resource limit")
	ErrShutdownTimeout      = errors.New("vtransport: callback did not stop before shutdown deadline")
)

type Config struct {
	Kind                                                   Kind
	Path, Host, ServiceName                                string
	EnableTun, EnableTunMulti                              bool
	MaxEarlyData                                           int // WS RawURL-base64 Sec-WebSocket-Protocol only; 0 disables.
	MaxConnections, MaxStreams, MaxHeaderBytes             int
	MaxMessageBytes, MaxProtoFields, WriteChunkBytes       int
	HTTP2ConnectionWindow, HTTP2StreamWindow               int32
	HeaderTimeout, IdleTimeout, IOTimeout, ShutdownTimeout time.Duration
}
type Metadata struct {
	Kind             Kind
	Path, Host, Mode string
	EarlyDataBytes   int
	RemoteAddr       string
}
type Handler func(context.Context, *Stream, Metadata) error

type Server struct {
	cfg      Config
	mu       sync.Mutex
	conns    map[net.Conn]bool
	streams  map[*Stream]bool
	running  bool
	stopped  bool
	http     *http.Server
	listener net.Listener
	ctx      context.Context
	change   chan struct{}
}
type Stats struct{ Connections, Streams int }

func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{len(s.conns), len(s.streams)}
}
func NewServer(c Config) (*Server, error) {
	if c.Kind != WebSocket && c.Kind != HTTPUpgrade && c.Kind != GRPC {
		return nil, ErrConfig
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Path[0] != '/' || len(c.Path) > 2048 || strings.ContainsAny(c.Path, "?#\r\n") {
		return nil, ErrConfig
	}
	if c.Kind == GRPC {
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`).MatchString(c.ServiceName) {
			return nil, fmt.Errorf("%w: simple serviceName required", ErrConfig)
		}
		if !c.EnableTun && !c.EnableTunMulti {
			c.EnableTun = true
			c.EnableTunMulti = true
		}
	}
	if c.MaxEarlyData < 0 || c.MaxEarlyData > 8192 {
		return nil, ErrConfig
	}
	if c.Kind != WebSocket && c.MaxEarlyData != 0 {
		return nil, ErrConfig
	}
	for _, v := range []struct {
		p *int
		d int
	}{{&c.MaxConnections, 16}, {&c.MaxStreams, 16}, {&c.MaxHeaderBytes, 16384}, {&c.MaxMessageBytes, 1048576}, {&c.MaxProtoFields, 256}, {&c.WriteChunkBytes, 16384}} {
		if *v.p < 0 {
			return nil, ErrConfig
		}
		if *v.p == 0 {
			*v.p = v.d
		}
	}
	if c.MaxMessageBytes > 16*1024*1024 || c.WriteChunkBytes > c.MaxMessageBytes-16 || c.MaxHeaderBytes < 512 || c.MaxProtoFields > 4096 {
		return nil, ErrConfig
	}
	if c.HTTP2ConnectionWindow == 0 {
		c.HTTP2ConnectionWindow = 1048576
	}
	if c.HTTP2StreamWindow == 0 {
		c.HTTP2StreamWindow = 131072
	}
	if c.HTTP2ConnectionWindow < 65535 || c.HTTP2StreamWindow < 65535 {
		return nil, ErrConfig
	}
	for _, v := range []struct {
		p *time.Duration
		d time.Duration
	}{{&c.HeaderTimeout, 5 * time.Second}, {&c.IdleTimeout, 30 * time.Second}, {&c.IOTimeout, 10 * time.Second}, {&c.ShutdownTimeout, 3 * time.Second}} {
		if *v.p < 0 {
			return nil, ErrConfig
		}
		if *v.p == 0 {
			*v.p = v.d
		}
	}
	return &Server{cfg: c, conns: make(map[net.Conn]bool), streams: make(map[*Stream]bool), change: make(chan struct{})}, nil
}

type connKey struct{}
type boundedListener struct {
	net.Listener
	s *Server
}

func (l boundedListener) Accept() (net.Conn, error) {
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
		_ = c.SetDeadline(time.Now().Add(l.s.cfg.HeaderTimeout))
		return c, nil
	}
}
func (s *Server) releaseConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.notify()
	one, single := s.listener.(*oneListener)
	empty := len(s.conns) == 0
	s.mu.Unlock()
	if single && empty {
		_ = one.Close()
	}
}

func (s *Server) notify() { close(s.change); s.change = make(chan struct{}) }

// Serve owns listener and all accepted connections. Supply a TLS listener whose
// ALPN includes http/1.1 (WS/Upgrade) or h2 (gRPC); certificates and 0-RTT policy
// belong to the caller. Server does not create a TLS configuration or downgrade.
// It is one-shot. On cancellation all connections/streams close immediately,
// then callbacks get at most ShutdownTimeout to return.
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
	hs := &http.Server{ReadHeaderTimeout: s.cfg.HeaderTimeout, IdleTimeout: s.cfg.IdleTimeout, MaxHeaderBytes: s.cfg.MaxHeaderBytes,
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handle(w, r, h) }),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, connKey{}, c) },
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				s.releaseConn(c)
			}
		},
	}
	s.http = hs
	if s.cfg.Kind == GRPC {
		if e := http2.ConfigureServer(hs, &http2.Server{MaxConcurrentStreams: uint32(s.cfg.MaxStreams), MaxReadFrameSize: 16384, MaxUploadBufferPerConnection: s.cfg.HTTP2ConnectionWindow, MaxUploadBufferPerStream: s.cfg.HTTP2StreamWindow, IdleTimeout: s.cfg.IdleTimeout, WriteByteTimeout: s.cfg.IOTimeout}); e != nil {
			return e
		}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.closeAll()
		case <-done:
		}
	}()
	err := hs.Serve(boundedListener{l, s})
	close(done)
	s.closeAll()
	until := time.NewTimer(s.cfg.ShutdownTimeout)
	defer until.Stop()
	for {
		s.mu.Lock()
		n := len(s.streams)
		changed := s.change
		s.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-changed:
		case <-until.C:
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
	listener := s.listener
	httpServer := s.http
	var conns []net.Conn
	for c := range s.conns {
		conns = append(conns, c)
	}
	var streams []*Stream
	for st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
	for _, st := range streams {
		_ = st.Close()
	}
	for _, c := range conns {
		c.Close()
		s.releaseConn(c)
	}
	if httpServer != nil {
		_ = httpServer.Close()
	}
}
func (s *Server) admit(st *Stream) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || len(s.streams) >= s.cfg.MaxStreams {
		return false
	}
	s.streams[st] = true
	return true
}
func (s *Server) finish(st *Stream) {
	st.Close()
	s.mu.Lock()
	delete(s.streams, st)
	s.notify()
	s.mu.Unlock()
}
func (s *Server) handle(w http.ResponseWriter, r *http.Request, h Handler) {
	if s.cfg.Host != "" && !equalHost(r.Host, s.cfg.Host) {
		http.NotFound(w, r)
		return
	}
	if s.cfg.Kind != GRPC && r.URL.Path != s.cfg.Path {
		http.NotFound(w, r)
		return
	}
	if s.cfg.Kind == GRPC {
		s.grpc(w, r, h)
		return
	}
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "invalid upgrade request", 400)
		return
	}
	if s.cfg.Kind == WebSocket {
		s.websocket(w, r, h)
	} else {
		s.upgrade(w, r, h)
	}
}
func equalHost(actual, expected string) bool {
	host, port, e := net.SplitHostPort(expected)
	if e == nil {
		other, otherPort, e := net.SplitHostPort(actual)
		return e == nil && port == otherPort && stringsEqualFold(host, other)
	}
	if h, _, e := net.SplitHostPort(actual); e == nil {
		actual = h
	}
	return len(actual) > 0 && stringsEqualFold(actual, expected)
}

func stringsEqualFold(a, b string) bool { // ASCII HTTP host comparison, no DNS/trust inference.
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

// ServeConn adapts a single caller-provided TLS connection, without listening or
// taking another connection. The same HTTP/ALPN and cancellation rules apply.
func (s *Server) ServeConn(ctx context.Context, c net.Conn, h Handler) error {
	if c == nil {
		return ErrConfig
	}
	l := &oneListener{c: c, closed: make(chan struct{})}
	return s.Serve(ctx, l, h)
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

var _ io.Closer = (*Stream)(nil)
