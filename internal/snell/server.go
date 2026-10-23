// Package snell implements the Snell v4/v5 conventional TCP wire subset.
// It owns framing and authenticated request lifetimes, never listening or dialing.
package snell

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var ErrReplay = errors.New("snell: repeated salt")
var ErrDeadlineUnsupported = errors.New("snell: transport has no deadline support")

const (
	Ping      byte = 0
	Connect   byte = 1
	ConnectV2 byte = 5
	UDP       byte = 6
)

type Config struct {
	PSK            []byte
	Obfs           string        // "none" (default) or "http". No TLS obfuscation.
	MaxSessions    int           // default 1024, includes handshakes
	MaxRequests    int           // default 1024 per physical connection
	ReplayCapacity int           // default 4096; full cache fails closed
	ReplayTTL      time.Duration // default 10 minutes; not a comprehensive replay guarantee
	DrainLimit     int           // default 512 KiB; only Finish discards old target data
}
type replayEntry struct {
	salt    [16]byte
	expires time.Time
}
type Server struct {
	cfg         Config
	slots       chan struct{}
	replayMu    sync.Mutex
	seen        map[[16]byte]struct{}
	ring        []replayEntry
	head, count int
}

func NewServer(c Config) (*Server, error) {
	if len(c.PSK) == 0 || len(c.PSK) > 4096 {
		return nil, ErrLimit
	}
	if c.Obfs == "" {
		c.Obfs = "none"
	}
	if c.Obfs != "none" && c.Obfs != "http" {
		return nil, ErrProtocol
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 1024
	}
	if c.MaxRequests == 0 {
		c.MaxRequests = 1024
	}
	if c.ReplayCapacity == 0 {
		c.ReplayCapacity = 4096
	}
	if c.ReplayTTL == 0 {
		c.ReplayTTL = 10 * time.Minute
	}
	if c.DrainLimit == 0 {
		c.DrainLimit = 512 * 1024
	}
	if c.MaxSessions < 1 || c.MaxSessions > 65536 || c.MaxRequests < 1 || c.MaxRequests > 1<<20 || c.ReplayCapacity < 1 || c.ReplayCapacity > 1<<20 || c.ReplayTTL < time.Second || c.ReplayTTL > 24*time.Hour || c.DrainLimit < 1 || c.DrainLimit > 16*1024*1024 {
		return nil, ErrLimit
	}
	c.PSK = bytes.Clone(c.PSK)
	return &Server{cfg: c, slots: make(chan struct{}, c.MaxSessions), seen: make(map[[16]byte]struct{}), ring: make([]replayEntry, c.ReplayCapacity)}, nil
}
func (s *Server) remember(salt [16]byte) error {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	now := time.Now()
	for s.count > 0 && !s.ring[s.head].expires.After(now) {
		delete(s.seen, s.ring[s.head].salt)
		s.head = (s.head + 1) % len(s.ring)
		s.count--
	}
	if _, ok := s.seen[salt]; ok {
		return ErrReplay
	}
	if s.count == len(s.ring) {
		return ErrLimit
	}
	s.ring[(s.head+s.count)%len(s.ring)] = replayEntry{salt, now.Add(s.cfg.ReplayTTL)}
	s.count++
	s.seen[salt] = struct{}{}
	return nil
}

// Accept assumes ownership of conn, including on failure. It verifies the first
// authenticated record before returning. Next exposes its authenticated request.
func (s *Server) Accept(conn io.ReadWriteCloser) (*Session, error) {
	return s.AcceptContext(context.Background(), conn)
}
func (s *Server) AcceptContext(ctx context.Context, conn io.ReadWriteCloser) (ss *Session, err error) {
	if conn == nil {
		return nil, ErrState
	}
	if ctx == nil {
		conn.Close()
		return nil, ErrState
	}
	select {
	case s.slots <- struct{}{}:
	default:
		conn.Close()
		return nil, ErrLimit
	}
	x := &Session{server: s, raw: conn, transport: conn}
	if s.cfg.Obfs == "http" {
		x.transport = &httpTransport{ReadWriteCloser: conn, r: bufio.NewReaderSize(conn, 4096)}
	}
	x.w = recordWriter{dst: x.transport, psk: s.cfg.PSK}
	x.cancelMu.Lock()
	x.stopCancel = context.AfterFunc(ctx, func() { _ = x.Close() })
	x.cancelMu.Unlock()
	defer func() {
		if err != nil {
			_ = x.Close()
		}
	}()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	var salt [16]byte
	if _, err = io.ReadFull(x.transport, salt[:]); err != nil {
		return nil, err
	}
	a, e := aeadFor(s.cfg.PSK, salt[:])
	if e != nil {
		return nil, e
	}
	x.r = recordReader{src: x.transport, a: a}
	x.pending, err = x.r.next()
	if err != nil {
		return nil, err
	}
	if err = s.remember(salt); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return x, nil
}

type Session struct {
	server         *Server
	raw, transport io.ReadWriteCloser
	r              recordReader
	w              recordWriter
	mu             sync.Mutex
	pending        []byte
	active         *Request
	requests       int
	closed         atomic.Bool
	once           sync.Once
	closeErr       error
	cancelMu       sync.Mutex
	stopCancel     func() bool
}

// Close aborts all blocking I/O (the supplied transport must obey Close semantics).
func (s *Session) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.cancelMu.Lock()
		if s.stopCancel != nil {
			s.stopCancel()
		}
		s.cancelMu.Unlock()
		s.closeErr = s.raw.Close()
		<-s.server.slots
	})
	return s.closeErr
}
func (s *Session) SetDeadline(t time.Time) error {
	if d, ok := s.raw.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return ErrDeadlineUnsupported
}
func (s *Session) SetReadDeadline(t time.Time) error {
	if d, ok := s.raw.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}
func (s *Session) SetWriteDeadline(t time.Time) error {
	if d, ok := s.raw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

// Next is sequential, and refuses to advance until the previous request Finish.
// Ping is handled internally and returns io.EOF after sending Pong and closing.
func (s *Session) Next() (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	if s.active != nil {
		return nil, ErrState
	}
	if s.requests >= s.server.cfg.MaxRequests {
		s.Close()
		return nil, ErrLimit
	}
	b := s.pending
	s.pending = nil
	if b == nil {
		var e error
		b, e = s.r.next()
		if e != nil {
			s.Close()
			return nil, e
		}
	}
	s.requests++
	q, e := parseRequest(b)
	if e != nil {
		_ = s.w.packet(errorReply(1, "invalid request"))
		s.Close()
		return nil, e
	}
	q.session = s
	if q.Command == Ping {
		e = s.w.packet([]byte{1})
		s.Close()
		if e != nil {
			return nil, e
		}
		return nil, io.EOF
	}
	s.active = q
	return q, nil
}
func errorReply(code byte, message string) []byte {
	if len(message) > 255 {
		message = message[:255]
	}
	return append([]byte{2, code, byte(len(message))}, message...)
}

type Request struct {
	Command         byte
	ClientID        []byte  // opaque client metadata, NOT a separate authenticated user ID
	Target          Address // only CONNECT/CONNECTv2
	session         *Session
	readMu, writeMu sync.Mutex
	cache           []byte
	readEOF         bool
	readRecords     int
	approved        bool
	replied         bool
	writeEOF        bool
	finished        atomic.Bool
}

func parseRequest(b []byte) (*Request, error) {
	if len(b) < 3 || b[0] != 1 {
		return nil, ErrProtocol
	}
	q := &Request{Command: b[1]}
	if q.Command == Ping {
		return q, nil
	}
	n := int(b[2])
	if len(b) < 3+n {
		return nil, ErrProtocol
	}
	q.ClientID = bytes.Clone(b[3 : 3+n])
	b = b[3+n:]
	switch q.Command {
	case Connect, ConnectV2:
		a, tail, e := parseConnect(b)
		if e != nil {
			return nil, e
		}
		q.Target = a
		q.cache = tail
	case UDP:
		if len(b) != 0 {
			return nil, ErrProtocol
		}
	default:
		return nil, ErrProtocol
	}
	return q, nil
}

// Approve marks a successful core policy/dial decision without writing a response.
// First Write sends Tunnel+payload, supporting server-first protocols. For UDP or
// explicit handshake completion call SendSuccess after Approve.
func (q *Request) Approve() error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.finished.Load() || q.writeEOF || q.session.closed.Load() {
		return ErrState
	}
	q.approved = true
	return nil
}
func (q *Request) SendSuccess() error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	return q.successLocked(nil)
}
func (q *Request) successLocked(data []byte) error {
	if !q.approved || q.finished.Load() || q.writeEOF || q.session.closed.Load() {
		return ErrState
	}
	if !q.replied {
		data = append([]byte{0}, data...)
		q.replied = true
	}
	if _, e := q.session.w.stream(data); e != nil {
		q.session.Close()
		return e
	}
	return nil
}

// Reject sends an authenticated error before any success reply, then closes.
func (q *Request) Reject(code byte, message string) error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.replied || q.finished.Load() {
		return ErrState
	}
	e := q.session.w.packet(errorReply(code, message))
	q.finished.Store(true)
	q.session.Close()
	return e
}
func (q *Request) Read(p []byte) (int, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	if q.Command == UDP || q.finished.Load() {
		return 0, ErrState
	}
	if len(p) == 0 {
		return 0, nil
	}
	if q.readEOF {
		return 0, io.EOF
	}
	if len(q.cache) == 0 {
		b, e := q.session.r.next()
		if e != nil {
			if e == io.EOF && (q.session.r.zero || q.Command == Connect) {
				q.readEOF = true
			} else {
				q.session.Close()
				if e == io.EOF {
					e = io.ErrUnexpectedEOF
				}
			}
			return 0, e
		}
		q.cache = b
	}
	n := copy(p, q.cache)
	q.cache = q.cache[n:]
	return n, nil
}
func (q *Request) Write(p []byte) (int, error) {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.Command == UDP {
		return 0, ErrState
	}
	if len(p) == 0 {
		if !q.approved || q.writeEOF || q.finished.Load() {
			return 0, ErrState
		}
		return 0, nil
	}
	// Never allocate proportional to a caller-controlled large stream write.
	if !q.replied {
		n := min(len(p), MaxPayload-1)
		if e := q.successLocked(p[:n]); e != nil {
			return 0, e
		}
		if n == len(p) {
			return n, nil
		}
		m, e := q.session.w.stream(p[n:])
		if e != nil {
			q.session.Close()
		}
		return n + m, e
	}
	if !q.approved || q.writeEOF || q.finished.Load() {
		return 0, ErrState
	}
	n, e := q.session.w.stream(p)
	if e != nil {
		q.session.Close()
	}
	return n, e
}
func (q *Request) CloseWrite() error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	return q.closeWriteLocked()
}
func (q *Request) closeWriteLocked() error {
	if q.finished.Load() {
		return ErrState
	}
	if q.writeEOF {
		return nil
	}
	q.writeEOF = true
	if !q.replied {
		code, msg := byte(0x65), "Remote EOF"
		if q.Command == Connect {
			code, msg = 0xff, "end of file"
		}
		e := q.session.w.packet(errorReply(code, msg))
		q.session.Close()
		return e
	}
	if q.Command != ConnectV2 {
		return q.session.Close()
	}
	if e := q.session.w.end(); e != nil {
		q.session.Close()
		return e
	}
	return nil
}

// Finish must be called after the caller joins both copy directions. It sends
// output EOF, then drains at most DrainLimit bytes / 1024 records to input zero.
// No old target bytes can be interpreted as the next request. It may block;
// use deadline/context or Close. A UDP or command-1 request ends the session.
func (q *Request) Finish() error {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.finished.Load() {
		return ErrState
	}
	if e := q.closeWriteLocked(); e != nil {
		q.finished.Store(true)
		return e
	}
	if q.Command != ConnectV2 || q.session.closed.Load() {
		q.finished.Store(true)
		return q.session.Close()
	}
	discarded := len(q.cache)
	q.cache = nil
	for !q.readEOF {
		if discarded > q.session.server.cfg.DrainLimit || q.readRecords >= 1024 {
			q.session.Close()
			q.finished.Store(true)
			return ErrLimit
		}
		b, e := q.session.r.next()
		q.readRecords++
		if e == io.EOF && q.session.r.zero {
			q.readEOF = true
			break
		}
		if e != nil {
			q.session.Close()
			q.finished.Store(true)
			return e
		}
		discarded += len(b)
	}
	if discarded > q.session.server.cfg.DrainLimit {
		q.session.Close()
		q.finished.Store(true)
		return ErrLimit
	}
	q.finished.Store(true)
	q.session.mu.Lock()
	q.session.active = nil
	q.session.mu.Unlock()
	return nil
}

// Close aborts the physical session; unlike Finish it never attempts reuse.
func (q *Request) Close() error { return q.session.Close() }
