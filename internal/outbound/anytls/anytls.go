// Package anytls is Kat's independently written AnyTLS client outbound: v2
// sessions over TLS carrying logical TCP streams, a bounded idle-session pool,
// and UDP via UoT v2 (non-connected mode).
//
// Session reuse follows the reference semantics: every active stream (TCP or
// UoT) owns a session exclusively; when the stream ends its session returns to
// the idle pool (most recently used first, at most idle_sessions, expiring
// after idle_timeout). Concurrent streams therefore use distinct sessions, so a
// slow reader can only stall its own TLS connection (AnyTLS has no per-stream
// flow control). Every connection to the server
// goes through the supplied under dialer, so chaining (via) works for TCP and UDP.
//
// Wire behavior follows the public AnyTLS protocol description and Kat's own
// server (internal/anytls); no upstream implementation code is used.
package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/internal/tlsclient"
)

const (
	typeName            = "anytls"
	defaultIdleSessions = 4
	maxIdleSessions     = 32
	defaultIdleTimeout  = 30 * time.Second
	minIdleTimeout      = time.Second
	maxIdleTimeout      = 10 * time.Minute
	maxPasswordBytes    = 4096
	// Applied only when the caller's context carries no deadline.
	defaultDialTimeout = 20 * time.Second
)

var (
	errProtocol   = errors.New("anytls: protocol violation from server")
	errNoResponse = errors.New("anytls: server did not respond")
)

func configError(msg string) error { return errors.New("anytls outbound: " + msg) }

// Validate statically checks an anytls outbound entry (it may read the CA file).
func Validate(o outbound.Options) error {
	if o.Type != typeName {
		return configError("type must be anytls")
	}
	if o.Name == "" {
		return configError("name is required")
	}
	if !validServerHost(o.Server) {
		return configError("invalid server")
	}
	if o.Port == 0 {
		return configError("port is required")
	}
	if o.Password == "" || len(o.Password) > maxPasswordBytes {
		return configError("password is required (at most 4096 bytes)")
	}
	if o.Username != "" || o.Method != "" || o.Key != "" {
		return configError("username/method/key are not applicable to anytls")
	}
	if o.TLS == nil {
		return configError("tls is required")
	}
	if o.TLS.ServerName != "" && !validServerHost(o.TLS.ServerName) {
		return configError("invalid tls.server_name")
	}
	if o.IdleSessions < 0 || o.IdleSessions > maxIdleSessions {
		return configError("idle_sessions must be 1..32")
	}
	if t := o.IdleTimeout.Value(); t != 0 && (t < minIdleTimeout || t > maxIdleTimeout) {
		return configError("idle_timeout must be 1s..10m")
	}
	if _, e := o.TLS.ClientConfig(o.ServerAddr().Host); e != nil {
		return configError("invalid tls options")
	}
	if tlsclient.Validate(o.TLS.Fingerprint) != nil {
		return configError("invalid tls.fingerprint")
	}
	return nil
}

func validServerHost(h string) bool {
	if h == "" {
		return false
	}
	if ip, e := netip.ParseAddr(h); e == nil {
		return ip.Zone() == ""
	}
	name := strings.TrimSuffix(h, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Outbound is the AnyTLS client. It is safe for concurrent use.
type Outbound struct {
	name        string
	server      outbound.Addr
	digest      [32]byte
	tls         *tls.Config
	fp          string // uTLS fingerprint ("" = crypto/tls)
	under       outbound.Dialer
	udp         bool
	idleMax     int
	idleTimeout time.Duration

	scheme atomic.Pointer[paddingScheme]

	mu       sync.Mutex
	sessions []*session
	closed   bool

	// Observability for tests.
	sessionsCreated atomic.Int64
	paddingUpdates  atomic.Int64
}

// New builds the outbound without any network I/O.
func New(o outbound.Options, under outbound.Dialer) (outbound.Outbound, error) {
	if e := Validate(o); e != nil {
		return nil, e
	}
	if under == nil {
		return nil, configError("under dialer is required")
	}
	server := o.ServerAddr()
	tc, e := o.TLS.ClientConfig(server.Host)
	if e != nil {
		return nil, configError("invalid tls options")
	}
	scheme, e := parsePaddingScheme(A.DefaultPaddingScheme)
	if e != nil {
		return nil, e
	}
	ob := &Outbound{
		name: o.Name, server: server, digest: sha256.Sum256([]byte(o.Password)), tls: tc, fp: o.TLS.Fingerprint, under: under,
		udp: o.UDPEnabled(), idleMax: o.IdleSessions, idleTimeout: o.IdleTimeout.Value(),
	}
	if ob.idleMax == 0 {
		ob.idleMax = defaultIdleSessions
	}
	if ob.idleTimeout == 0 {
		ob.idleTimeout = defaultIdleTimeout
	}
	ob.scheme.Store(scheme)
	return ob, nil
}

func (o *Outbound) Name() string { return o.name }
func (o *Outbound) Type() string { return typeName }

// UDP is configuration only: UoT rides a TCP stream, so any TCP chain carries it.
func (o *Outbound) UDP() bool { return o.udp }

// DialTCP opens a logical stream to dst. It returns after the server
// acknowledged the stream (v2 SYNACK); a SYNACK carrying an error fails the dial.
func (o *Outbound) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	target, e := appendAddr(nil, dst, socksTypes)
	if e != nil {
		return nil, e
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	st, e := o.open(ctx, target, true)
	if e != nil {
		return nil, e
	}
	return st, nil
}

// ListenPacket opens a UoT v2 stream in non-connected mode. The UoT request
// (whose advisory destination is the first datagram's destination) is sent with
// the first WriteTo, because servers may route the stream only after it.
func (o *Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if !o.udp {
		return nil, outbound.ErrUDPUnsupported
	}
	target, _ := appendAddr(nil, outbound.Addr{Host: A.MagicUDPHost}, socksTypes)
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	st, e := o.open(ctx, target, false)
	if e != nil {
		return nil, e
	}
	return &packetConn{st: st}, nil
}

// Close shuts down idle sessions and stops pooling. In-flight streams are owned
// by their callers; their sessions close when the last stream closes.
func (o *Outbound) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	var idle []*session
	kept := o.sessions[:0]
	for _, s := range o.sessions {
		if s.reserved == 0 {
			s.stopIdleLocked()
			idle = append(idle, s)
		} else {
			kept = append(kept, s)
		}
	}
	o.sessions = kept
	o.mu.Unlock()
	for _, s := range idle {
		s.fail(net.ErrClosed)
		s.wg.Wait()
	}
	return nil
}

func withDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultDialTimeout)
}

// open places a new stream on a pooled or new session and waits for the server.
// A pooled session that turns out to be dead (e.g. the server restarted while
// it sat idle) is dropped and the next idle or a fresh session is tried; the
// loop ends at the first fresh session, so it is bounded by the pool size.
func (o *Outbound) open(ctx context.Context, target []byte, tcp bool) (*stream, error) {
	var last error
	for attempt := 0; attempt <= maxIdleSessions+1; attempt++ {
		s, fresh, e := o.acquire(ctx)
		if e != nil {
			return nil, e
		}
		st, e := s.openStream(target)
		if e != nil {
			o.release(s)
			if !fresh && ctx.Err() == nil {
				last = e
				continue
			}
			return nil, e
		}
		e = st.await(ctx, tcp)
		if e == nil {
			return st, nil
		}
		_ = st.Close()
		var se *sessionError
		if errors.As(e, &se) && !fresh && ctx.Err() == nil {
			last = e
			continue
		}
		return nil, e
	}
	return nil, last
}

// acquire takes the most recently used idle session out of the idle pool, or
// dials a new session. A session carries at most one active stream, so
// concurrent dials never wait for each other.
func (o *Outbound) acquire(ctx context.Context) (*session, bool, error) {
	if s, e := o.pick(); s != nil || e != nil {
		return s, false, e
	}
	s, e := o.dialSession(ctx)
	if e != nil {
		return nil, false, e
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		s.fail(net.ErrClosed)
		return nil, false, net.ErrClosed
	}
	s.reserved = 1
	s.lastUsed = time.Now()
	o.sessions = append(o.sessions, s)
	o.mu.Unlock()
	return s, true, nil
}

func (o *Outbound) pick() (*session, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, net.ErrClosed
	}
	var best *session
	for _, s := range o.sessions {
		if s.failed.Load() || s.reserved != 0 { // only idle sessions are reusable
			continue
		}
		if best == nil || s.lastUsed.After(best.lastUsed) {
			best = s
		}
	}
	if best != nil {
		best.stopIdleLocked() // leaves the idle pool while its stream is active
		best.reserved = 1
		best.lastUsed = time.Now()
	}
	return best, nil
}

// release returns a stream slot; a session left without streams becomes idle
// (bounded count, timed expiry) or closes when the outbound is closed.
func (o *Outbound) release(s *session) {
	var closing []*session
	o.mu.Lock()
	s.reserved--
	if s.failed.Load() {
		// A session can fail before acquire registered it; drop it here.
		o.removeLocked(s)
	} else if s.reserved == 0 && o.removable(s) {
		s.lastUsed = time.Now()
		if o.closed {
			o.removeLocked(s)
			closing = append(closing, s)
		} else {
			s.idleGen++
			gen := s.idleGen
			s.idleTimer = time.AfterFunc(o.idleTimeout, func() { o.expire(s, gen) })
			closing = o.trimIdleLocked()
		}
	}
	o.mu.Unlock()
	for _, x := range closing {
		x.fail(errIdleClosed)
	}
}

var errIdleClosed = errors.New("anytls: idle session closed")

func (o *Outbound) removable(s *session) bool {
	for _, x := range o.sessions {
		if x == s {
			return true
		}
	}
	return false
}

func (o *Outbound) expire(s *session, gen uint64) {
	o.mu.Lock()
	ok := s.idleGen == gen && s.reserved == 0 && o.removable(s)
	if ok {
		o.removeLocked(s)
	}
	o.mu.Unlock()
	if ok {
		s.fail(errIdleClosed)
	}
}

// trimIdleLocked closes the least recently used idle sessions above idleMax.
func (o *Outbound) trimIdleLocked() []*session {
	var idle []*session
	for _, s := range o.sessions {
		if s.reserved == 0 && !s.failed.Load() {
			idle = append(idle, s)
		}
	}
	var out []*session
	for len(idle) > o.idleMax {
		oldest := 0
		for i, s := range idle {
			if s.lastUsed.Before(idle[oldest].lastUsed) {
				oldest = i
			}
		}
		s := idle[oldest]
		idle = append(idle[:oldest], idle[oldest+1:]...)
		o.removeLocked(s)
		out = append(out, s)
	}
	return out
}

func (o *Outbound) removeLocked(s *session) {
	s.stopIdleLocked()
	for i, x := range o.sessions {
		if x == s {
			o.sessions = append(o.sessions[:i], o.sessions[i+1:]...)
			return
		}
	}
}

func (o *Outbound) removeSession(s *session) {
	o.mu.Lock()
	o.removeLocked(s)
	o.mu.Unlock()
}

// dialSession connects through under, completes TLS and sends the
// authentication packet (packet 0). Settings ride with the first SYN.
func (o *Outbound) dialSession(ctx context.Context) (*session, error) {
	raw, e := o.under.DialTCP(ctx, o.server)
	if e != nil {
		return nil, fmt.Errorf("anytls: dial server: %w", e)
	}
	tc, e := tlsclient.Handshake(ctx, raw, o.tls, o.fp)
	if e != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("anytls: tls handshake: %w", e)
	}
	scheme := o.scheme.Load()
	pad := scheme.authPadding()
	auth := make([]byte, 0, 34+pad)
	auth = append(auth, o.digest[:]...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(pad))
	auth = append(auth, make([]byte, pad)...)
	if dl, ok := ctx.Deadline(); ok {
		_ = tc.SetWriteDeadline(dl)
	}
	e = writeAll(tc, auth)
	_ = tc.SetWriteDeadline(time.Time{})
	if e != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("anytls: send authentication: %w", e)
	}
	settings := "v=2\nclient=kat\npadding-md5=" + scheme.md5
	s := newSession(o, tc, scheme, appendFrame(nil, cmdSettings, 0, []byte(settings)))
	o.sessionsCreated.Add(1)
	s.start()
	return s, nil
}

// sessionCount reports live pooled sessions (busy, idle) for tests.
func (o *Outbound) sessionCount() (busy, idle int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, s := range o.sessions {
		if s.reserved > 0 {
			busy++
		} else {
			idle++
		}
	}
	return
}

var _ outbound.Outbound = (*Outbound)(nil)
