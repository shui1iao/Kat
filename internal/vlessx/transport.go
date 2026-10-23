// Package vlessx implements RAW VLESS extensions; it does not listen or route.
package vlessx

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	reality "github.com/xtls/reality"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrWire = errors.New("vlessx: malformed wire data")
var ErrLimit = errors.New("vlessx: resource limit")
var ErrState = errors.New("vlessx: invalid lifecycle state")
var ErrUnsupported = errors.New("vlessx: unsupported mode")

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type ownedConn struct {
	net.Conn
	done    chan struct{}
	once    sync.Once
	err     error
	onClose func()
}

func (c *ownedConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.err = c.Conn.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.err
}
func (c *ownedConn) CloseNotify() <-chan struct{} { return c.done }
func (c *ownedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return ErrUnsupported
}

// recordGate prevents ciphertext over-read from the first handshake byte.
// No reflect, unsafe, private field access, or standard library fork is used.
type recordGate struct {
	finalRecordBytes int
	*ownedConn
	header          [5]byte
	headerRead      int // consumed from socket, not yet published to TLS
	have, remaining int
	readDirect      bool
	writeMu         sync.Mutex
	writeDirect     bool
}

func (g *recordGate) Read(p []byte) (int, error) {
	if g.readDirect {
		return 0, ErrState
	}
	if len(p) == 0 {
		return 0, nil
	}
	if g.remaining == 0 && g.have == 0 {
		nread, e := io.ReadFull(g.ownedConn, g.header[g.headerRead:])
		g.headerRead += nread
		if e != nil {
			return 0, e
		}
		n := int(binary.BigEndian.Uint16(g.header[3:]))
		if n == 0 || n > 18432 {
			return 0, ErrLimit
		}
		g.remaining = n
		g.have = 5
		g.headerRead = 0
	}
	if g.have > 0 {
		off := 5 - g.have
		n := copy(p, g.header[off:])
		g.have -= n
		return n, nil
	}
	n, e := g.ownedConn.Read(p[:min(len(p), g.remaining)])
	g.remaining -= n
	return n, e
}
func (g *recordGate) Write(p []byte) (int, error) {
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	if g.writeDirect {
		g.Close()
		return 0, ErrState
	}
	if g.finalRecordBytes != 0 {
		if len(p) != g.finalRecordBytes || len(p) < 5 || p[0] != 23 || int(binary.BigEndian.Uint16(p[3:5])) != len(p)-5 {
			g.Close()
			return 0, ErrState
		}
		if e := writeFull(g.ownedConn, p); e != nil {
			g.Close()
			return 0, e
		}
		g.finalRecordBytes = 0
		g.writeDirect = true
		return len(p), nil
	}
	return g.ownedConn.Write(p)
}
func (g *recordGate) rawWrite(p []byte) (int, error) {
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	if !g.writeDirect {
		return 0, ErrState
	}
	return g.ownedConn.Write(p)
}

// Transport owns its connection. Construct it BEFORE the outer TLS handshake.
// Close is an abort (no TLS alert after raw transition); CloseWrite is graceful.
// One Read and one Write may run concurrently; switching occurs in that direction.
type Transport struct {
	secure          net.Conn
	gate            *recordGate
	readMu, writeMu sync.Mutex
	cache           []byte
	terminal        error
	rd, wd          bool
	closedWrite     bool
	once            sync.Once
	stop            func() bool
}

func newTransport(ctx context.Context, c net.Conn, release ...func()) *Transport {
	own := &ownedConn{Conn: c, done: make(chan struct{})}
	if len(release) > 0 {
		own.onClose = release[0]
	}
	g := &recordGate{ownedConn: own}
	t := &Transport{gate: g}
	t.stop = context.AfterFunc(ctx, func() { own.Close() })
	return t
}

func cloneTLSConfigForGate(cfg *tls.Config) *tls.Config {
	local := cfg.Clone()
	local.DynamicRecordSizingDisabled = true
	if callback := local.GetConfigForClient; callback != nil {
		local.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			next, err := callback(hello)
			if err != nil || next == nil {
				return next, err
			}
			return cloneTLSConfigForGate(next), nil
		}
	}
	return local
}

// AcceptTLS requires TLS1.3 for Vision. cfg must contain normal server credentials.
// Caller sets a handshake deadline on c; ctx controls the complete lifetime.
func AcceptTLS(ctx context.Context, c net.Conn, cfg *tls.Config) (*Transport, error) {
	if c == nil {
		return nil, ErrState
	}
	if ctx == nil || cfg == nil {
		c.Close()
		return nil, ErrState
	}
	t := newTransport(ctx, c)
	local := cloneTLSConfigForGate(cfg)
	sc := tls.Server(t.gate, local)
	t.secure = sc
	if e := sc.HandshakeContext(ctx); e != nil {
		t.Close()
		return nil, e
	}
	return t, nil
}
func (t *Transport) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(t.cache) > 0 {
		n := copy(p, t.cache)
		t.cache = t.cache[n:]
		return n, nil
	}
	if t.terminal != nil {
		return 0, t.terminal
	}
	if t.rd {
		return t.gate.ownedConn.Read(p)
	}
	b := make([]byte, 16384)
	n, e := t.secure.Read(b)
	if n > 0 {
		t.cache = b[:n]
		t.terminal = e
		n = copy(p, t.cache)
		t.cache = t.cache[n:]
		return n, nil
	}
	return 0, e
}
func (t *Transport) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.closedWrite {
		return 0, io.ErrClosedPipe
	}
	if t.wd {
		return t.gate.rawWrite(p)
	}
	return t.secure.Write(p)
}
func (t *Transport) switchRead() error {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if t.gate.headerRead != 0 || t.gate.remaining != 0 || t.gate.have != 0 || t.terminal != nil {
		return ErrState
	}
	t.rd = true
	t.gate.readDirect = true
	return nil
}

// writeFinalVision atomically seals the last padded TLS record and closes
// the gate to TLS-originated writes before returning, including read-side KU.
func (t *Transport) writeFinalVision(p []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if len(p) < 6 || len(p) > 8192 || t.wd || t.closedWrite {
		return ErrState
	}
	t.gate.writeMu.Lock()
	if t.gate.writeDirect || t.gate.finalRecordBytes != 0 {
		t.gate.writeMu.Unlock()
		return ErrState
	}
	t.gate.finalRecordBytes = len(p) + 22
	t.gate.writeMu.Unlock()
	n, e := t.secure.Write(p)
	if e != nil || n != len(p) {
		t.Close()
		if e != nil {
			return e
		}
		return io.ErrShortWrite
	}
	t.gate.writeMu.Lock()
	ready := t.gate.writeDirect && t.gate.finalRecordBytes == 0
	t.gate.writeMu.Unlock()
	if !ready {
		t.Close()
		return ErrState
	}
	t.wd = true
	return nil
}
func (t *Transport) switchWrite() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.gate.writeMu.Lock()
	defer t.gate.writeMu.Unlock()
	if t.closedWrite {
		return ErrState
	}
	t.wd = true
	t.gate.writeDirect = true
	return nil
}
func (t *Transport) CloseWrite() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.closedWrite {
		return nil
	}
	t.closedWrite = true
	if t.wd {
		return t.gate.ownedConn.CloseWrite()
	}
	if w, ok := t.secure.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return ErrUnsupported
}
func (t *Transport) Close() error {
	var e error
	t.once.Do(func() {
		if t.stop != nil {
			t.stop()
		}
		e = t.gate.Close()
	})
	return e
}
func (t *Transport) TLSVersion() uint16 {
	switch c := t.secure.(type) {
	case *tls.Conn:
		return c.ConnectionState().Version
	case *reality.Conn:
		return c.ConnectionState().Version
	}
	return 0
}
func (t *Transport) LocalAddr() net.Addr                { return t.gate.LocalAddr() }
func (t *Transport) RemoteAddr() net.Addr               { return t.gate.RemoteAddr() }
func (t *Transport) SetDeadline(x time.Time) error      { return t.gate.SetDeadline(x) }
func (t *Transport) SetReadDeadline(x time.Time) error  { return t.gate.SetReadDeadline(x) }
func (t *Transport) SetWriteDeadline(x time.Time) error { return t.gate.SetWriteDeadline(x) }

type RealityConfig struct {
	PrivateKey                         []byte
	ShortIDs                           [][8]byte
	ServerNames                        []string
	Decoy                              netip.AddrPort // explicit loopback literal, never client supplied
	DecoyRoots                         *x509.CertPool // trust local decoy; no insecure skip verification
	MinClientVersion, MaxClientVersion []byte
	MaxTimeDiff                        time.Duration
	MaxSessions                        int
	HandshakeTimeout                   time.Duration
}
type RealityServer struct {
	cfg     *reality.Config
	slots   chan struct{}
	timeout time.Duration
}

// NewRealityServer performs bounded genuine TLS1.3 decoy preflight before use.
func NewRealityServer(ctx context.Context, c RealityConfig) (*RealityServer, error) {
	if ctx == nil || !c.Decoy.IsValid() || !c.Decoy.Addr().IsLoopback() || c.Decoy.Port() == 0 || c.DecoyRoots == nil {
		return nil, ErrState
	}
	if len(c.PrivateKey) != 32 || len(c.ShortIDs) == 0 || len(c.ShortIDs) > 16 || len(c.ServerNames) == 0 || len(c.ServerNames) > 8 {
		return nil, ErrLimit
	}
	priv, e := ecdh.X25519().NewPrivateKey(c.PrivateKey)
	if e != nil {
		return nil, e
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 64
	}
	if c.MaxSessions < 1 || c.MaxSessions > 4096 {
		return nil, ErrLimit
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	if c.HandshakeTimeout < time.Second || c.HandshakeTimeout > 30*time.Second {
		return nil, ErrLimit
	}
	if c.MaxTimeDiff == 0 {
		c.MaxTimeDiff = time.Minute
	}
	if c.MaxTimeDiff < time.Second || c.MaxTimeDiff > 10*time.Minute {
		return nil, ErrLimit
	}
	if len(c.MinClientVersion) != 0 && len(c.MinClientVersion) != 3 || len(c.MaxClientVersion) != 0 && len(c.MaxClientVersion) != 3 {
		return nil, ErrWire
	}
	if len(c.MinClientVersion) == 3 && len(c.MaxClientVersion) == 3 {
		for i := 0; i < 3; i++ {
			if c.MinClientVersion[i] < c.MaxClientVersion[i] {
				break
			}
			if c.MinClientVersion[i] > c.MaxClientVersion[i] {
				return nil, ErrWire
			}
		}
	}
	rc := &reality.Config{SessionTicketsDisabled: true, DynamicRecordSizingDisabled: true, Type: "tcp", Dest: c.Decoy.String(), PrivateKey: append([]byte{}, priv.Bytes()...), RootCAs: c.DecoyRoots.Clone(), ServerNames: map[string]bool{}, ShortIds: map[[8]byte]bool{}, MaxTimeDiff: c.MaxTimeDiff, MinClientVer: append([]byte(nil), c.MinClientVersion...), MaxClientVer: append([]byte(nil), c.MaxClientVersion...)}
	for _, n := range c.ServerNames {
		if !validHost(n) {
			return nil, ErrWire
		}
		if rc.ServerNames[n] {
			return nil, ErrWire
		}
		rc.ServerNames[n] = true
	}
	for _, s := range c.ShortIDs {
		if rc.ShortIds[s] {
			return nil, ErrWire
		}
		rc.ShortIds[s] = true
	}
	rc.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != c.Decoy.String() {
			return nil, ErrState
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", c.Decoy.String())
	}
	if e = reality.DetectPostHandshakeRecordsLensContext(ctx, rc); e != nil {
		return nil, e
	}
	return &RealityServer{cfg: rc, slots: make(chan struct{}, c.MaxSessions), timeout: c.HandshakeTimeout}, nil
}
func (s *RealityServer) Accept(ctx context.Context, c net.Conn) (*Transport, error) {
	if c == nil {
		return nil, ErrState
	}
	if ctx == nil {
		c.Close()
		return nil, ErrState
	}
	select {
	case s.slots <- struct{}{}:
	default:
		c.Close()
		return nil, ErrLimit
	}
	t := newTransport(ctx, c, func() { <-s.slots })
	deadline := time.Now().Add(s.timeout)
	if e := c.SetDeadline(deadline); e != nil {
		t.Close()
		return nil, e
	}
	hctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	secure, e := reality.Server(hctx, t.gate, s.cfg)
	if e != nil {
		t.Close()
		return nil, e
	}
	t.secure = secure
	if e = hctx.Err(); e != nil {
		t.Close()
		return nil, e
	}
	if e = c.SetDeadline(time.Time{}); e != nil {
		t.Close()
		return nil, e
	}
	return t, nil
}
