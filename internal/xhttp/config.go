// Package xhttp implements independently written, bounded XHTTP server byte
// streams. VLESS authentication, destination routing and TLS trust are external.
package xhttp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PacketUp  = "packet-up"
	StreamUp  = "stream-up"
	StreamOne = "stream-one"
	Auto      = "auto"
)

var (
	ErrConfig               = errors.New("xhttp: invalid configuration")
	ErrProtocol             = errors.New("xhttp: protocol violation")
	ErrLimit                = errors.New("xhttp: resource limit")
	ErrAssociation          = errors.New("xhttp: duplicate/foreign/retired association")
	ErrClosed               = errors.New("xhttp: session closed")
	ErrHalfCloseUnsupported = errors.New("xhttp: response half-close unsupported")
	ErrShutdownTimeout      = errors.New("xhttp: handler shutdown deadline exceeded")
)

type Config struct {
	Path, Host, Mode string
	NoSSEHeader      bool
	// Only fixed-Xray default metadata path / payload body placements currently.
	PaddingMin, PaddingMax                                                                       int // zero/zero => 100..1000; never disables validation.
	MaxConnections, MaxRequests, MaxSessions, MaxUnpaired, MaxHandlers, MaxRetired               int
	MaxHeaderBytes, MaxPacketBytes, MaxBufferedPackets, MaxBufferedBytes, MaxGlobalBufferedBytes int
	MaxUploads                                                                                   int
	MaxUploadBytes                                                                               int64
	HeaderTimeout, IdleTimeout, PairTimeout, IOTimeout, ShutdownTimeout, RetiredTTL              time.Duration
}
type Metadata struct {
	SessionID, Mode, RemoteIP string
	RemoteAddr                string
	HTTPMajor                 int
}
type Handler func(context.Context, *Stream, Metadata) error
type Stats struct{ Connections, Requests, Sessions, Unpaired, Handlers, BufferedPackets, BufferedBytes, Retired int }
type Server struct {
	cfg                                                Config
	mu                                                 sync.Mutex
	conns                                              map[net.Conn]bool
	sessions                                           map[string]*session
	retired                                            map[string]time.Time
	requests, handlers, bufferedPackets, bufferedBytes int
	ctx                                                context.Context
	listener                                           net.Listener
	http                                               *http.Server
	running, stopped                                   bool
	changed                                            chan struct{}
}

func NewServer(c Config) (*Server, error) {
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Path[0] != '/' || strings.ContainsAny(c.Path, "?#\r\n") || len(c.Path) > 1024 {
		return nil, ErrConfig
	}
	if !strings.HasSuffix(c.Path, "/") {
		c.Path += "/"
	}
	if c.Mode == "" {
		c.Mode = Auto
	}
	if c.Mode != Auto && c.Mode != PacketUp && c.Mode != StreamUp && c.Mode != StreamOne {
		return nil, ErrConfig
	}
	if c.PaddingMin == 0 && c.PaddingMax == 0 {
		c.PaddingMin = 100
		c.PaddingMax = 1000
	}
	if c.PaddingMin < 1 || c.PaddingMax < c.PaddingMin || c.PaddingMax > 8192 {
		return nil, ErrConfig
	}
	fields := []struct {
		p *int
		d int
	}{{&c.MaxConnections, 16}, {&c.MaxRequests, 16}, {&c.MaxSessions, 16}, {&c.MaxUnpaired, 8}, {&c.MaxHandlers, 16}, {&c.MaxRetired, 128}, {&c.MaxHeaderBytes, 16384}, {&c.MaxPacketBytes, 1000000}, {&c.MaxBufferedPackets, 32}, {&c.MaxBufferedBytes, 2000000}, {&c.MaxGlobalBufferedBytes, 16000000}, {&c.MaxUploads, 10000}}
	for _, v := range fields {
		if *v.p < 0 {
			return nil, ErrConfig
		}
		if *v.p == 0 {
			*v.p = v.d
		}
	}
	if c.MaxPacketBytes > 16*1024*1024 || c.MaxHeaderBytes < 512 || c.MaxBufferedPackets > 4096 {
		return nil, ErrConfig
	}
	if c.MaxUploadBytes < 0 || c.MaxUploadBytes > 1<<62 {
		return nil, ErrConfig
	}
	if c.MaxUploadBytes == 0 {
		c.MaxUploadBytes = 64 * 1024 * 1024
	}
	for _, v := range []struct {
		p *time.Duration
		d time.Duration
	}{{&c.HeaderTimeout, 5 * time.Second}, {&c.IdleTimeout, 30 * time.Second}, {&c.PairTimeout, 10 * time.Second}, {&c.IOTimeout, 10 * time.Second}, {&c.ShutdownTimeout, 3 * time.Second}, {&c.RetiredTTL, 60 * time.Second}} {
		if *v.p < 0 {
			return nil, ErrConfig
		}
		if *v.p == 0 {
			*v.p = v.d
		}
	}
	return &Server{cfg: c, conns: make(map[net.Conn]bool), sessions: make(map[string]*session), retired: make(map[string]time.Time), changed: make(chan struct{})}, nil
}
func (s *Server) notify() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireRetired(time.Now())
	unpaired := 0
	for _, ss := range s.sessions {
		ss.mu.Lock()
		if !ss.down || !ss.up {
			unpaired++
		}
		ss.mu.Unlock()
	}
	return Stats{len(s.conns), s.requests, len(s.sessions), unpaired, s.handlers, s.bufferedPackets, s.bufferedBytes, len(s.retired)}
}
func (s *Server) expireRetired(now time.Time) {
	for id, expiry := range s.retired {
		if !expiry.After(now) {
			delete(s.retired, id)
		}
	}
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func equalHost(actual, expected string) bool {
	if expected == "" {
		return true
	}
	host, port, e := net.SplitHostPort(expected)
	if e == nil {
		h, p, e := net.SplitHostPort(actual)
		return e == nil && p == port && strings.EqualFold(h, host)
	}
	if h, _, e := net.SplitHostPort(actual); e == nil {
		actual = h
	}
	return strings.EqualFold(actual, expected)
}
func (s *Server) meta(r *http.Request) (string, *uint64, error) {
	if !equalHost(r.Host, s.cfg.Host) || !strings.HasPrefix(r.URL.Path, s.cfg.Path) {
		return "", nil, ErrAssociation
	}
	padding := ""
	if referer := r.Header.Get("Referer"); referer != "" {
		u, e := url.Parse(referer)
		if e != nil {
			return "", nil, ErrProtocol
		}
		padding = u.Query().Get("x_padding")
	} else {
		padding = r.URL.Query().Get("x_padding")
	}
	if len(padding) < s.cfg.PaddingMin || len(padding) > s.cfg.PaddingMax {
		return "", nil, ErrProtocol
	}
	suffix := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, s.cfg.Path), "/")
	if suffix == "" {
		return "", nil, nil
	}
	parts := strings.Split(suffix, "/")
	if len(parts) > 2 || !uuidPattern.MatchString(parts[0]) {
		return "", nil, ErrProtocol
	}
	if len(parts) == 1 {
		return parts[0], nil, nil
	}
	seq := parts[1]
	if seq == "" || (len(seq) > 1 && seq[0] == '0') {
		return "", nil, ErrProtocol
	}
	v, e := strconv.ParseUint(seq, 10, 64)
	if e != nil {
		return "", nil, ErrProtocol
	}
	return parts[0], &v, nil
}
func (s *Server) responseHeaders(w http.ResponseWriter, down bool) error {
	draw, e := rand.Int(rand.Reader, big.NewInt(int64(s.cfg.PaddingMax-s.cfg.PaddingMin+1)))
	if e != nil {
		return e
	}
	size := s.cfg.PaddingMin + int(draw.Int64())
	w.Header().Set("X-Padding", strings.Repeat("X", size))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if down && !s.cfg.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	return nil
}
func peerIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return ""
	}
	return host
}
func httpError(w http.ResponseWriter, e error) {
	w.Header().Set("Connection", "close")
	code := 400
	if errors.Is(e, ErrLimit) {
		code = 429
	}
	if errors.Is(e, ErrAssociation) || errors.Is(e, ErrClosed) {
		code = 409
	}
	http.Error(w, fmt.Sprint(e), code)
}
