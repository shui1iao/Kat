package kernel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/sniff"
)

// sniffResult is what sniffing learned about one connection or UDP target.
type sniffResult struct {
	proto    string // tls | http | quic ("" = unknown)
	host     string // sniffed domain ("" = none)
	override bool   // replace an IP destination by host
}

type sniffKey struct{}

func withSniff(ctx context.Context, r *sniffResult) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, sniffKey{}, r)
}

func sniffOf(ctx context.Context) *sniffResult {
	r, _ := ctx.Value(sniffKey{}).(*sniffResult)
	return r
}

// target applies override_destination: an IP destination becomes the
// sniffed domain (the server resolves it). A domain destination is kept.
func (r *sniffResult) target(a Address) Address {
	if r == nil || !r.override || r.host == "" {
		return a
	}
	if _, e := netip.ParseAddr(a.Host); e != nil {
		return a
	}
	return Address{r.host, a.Port}
}

// sniffWanted reports whether the TCP stream to port must be sniffed. It is
// false without sniffing on the inbound, for ports not listed and when the
// result could not change anything (no rules and no override).
func (s *Server) sniffWanted(ctx context.Context, port uint16, udp bool) *SniffOptions {
	im := inboundMetaOf(ctx)
	if im == nil || im.sniff == nil {
		return nil
	}
	o := im.sniff
	l := o.tcp
	if udp {
		l = o.udp
	}
	if !l.Contains(port) {
		return nil
	}
	if !o.OverrideDestination && !s.networkPolicy() {
		return nil
	}
	return o
}

type readResult struct {
	b   []byte
	err error
}

// sniffStream reads the client's first data on a sniffed port, at most until
// the sniff timeout. It returns the context carrying the result, the client
// stream to relay from (wrapped only when a read is still pending at the
// timeout) and the bytes already read, which the caller forwards to the
// destination right after dialing. Reads run in a goroutine instead of using
// deadlines: a deadline error is sticky on some decoded streams.
func (s *Server) sniffStream(ctx context.Context, c net.Conn, target Address) (context.Context, net.Conn, []byte) {
	o := s.sniffWanted(ctx, target.Port, false)
	if o == nil {
		return ctx, c, nil
	}
	timer := time.NewTimer(o.Timeout.value())
	defer timer.Stop()
	var buf []byte
	res := &sniffResult{override: o.OverrideDestination}
	ch := make(chan readResult, 1)
	for {
		b := make([]byte, 4096)
		go func() {
			n, err := c.Read(b)
			ch <- readResult{b[:n], err}
		}()
		select {
		case r := <-ch:
			buf = append(buf, r.b...)
			proto, host, st := sniff.Stream(buf)
			if st == sniff.Done {
				res.proto, res.host = proto, host
			}
			if r.err != nil {
				return withSniff(ctx, res), &sniffedConn{Conn: c, err: r.err}, buf
			}
			if st != sniff.NeedMore || len(buf) >= sniff.MaxStream {
				return withSniff(ctx, res), c, buf
			}
		case <-timer.C:
			return withSniff(ctx, res), &sniffedConn{Conn: c, pending: ch}, buf
		}
	}
}

// sniffedConn delivers the outcome of the read that was still pending (or
// the error that ended sniffing) before reading from the stream again.
type sniffedConn struct {
	net.Conn
	mu      sync.Mutex
	pending chan readResult
	rest    []byte
	err     error
}

func (c *sniffedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		r := <-c.pending
		c.pending = nil
		c.rest, c.err = r.b, r.err
	}
	if len(c.rest) > 0 {
		n := copy(p, c.rest)
		c.rest = c.rest[n:]
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

func (c *sniffedConn) CloseWrite() error { return closeWrite(c.Conn) }

// forwardSniffed writes the bytes read while sniffing to the destination.
func forwardSniffed(ctx context.Context, out io.Writer, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	n, e := out.Write(b)
	up, _ := meters(ctx)
	up.add(n)
	return e
}

// ---- UDP (QUIC) ----

// udpSniffer sniffs QUIC per association and target. Every datagram to a
// target uses the same result, so a QUIC connection is routed consistently.
// While a ClientHello spans several Initial packets the target's datagrams
// are held, bounded by the sniff timeout, a count and a byte budget.
type udpSniffer struct {
	opt     *SniffOptions
	targets map[Address]*udpSniffState
	held    int // bytes held over all targets
	timer   *time.Timer
}

type udpSniffState struct {
	res     *sniffResult // decided; nil while sniffing
	q       *sniff.QUIC
	quic    bool // at least one Initial was decrypted
	held    []packet
	expires time.Time
	last    time.Time
}

const (
	maxUDPSniffTargets = 256
	maxHeldDatagrams   = 8
	maxHeldBytes       = 32 << 10
)

// newUDPSniffer returns nil when the association is not sniffed.
func (a *udpAssociation) newUDPSniffer() *udpSniffer {
	im := inboundMetaOf(a.ctx)
	if im == nil || im.sniff == nil || len(im.sniff.udp) == 0 {
		return nil
	}
	if !im.sniff.OverrideDestination && !a.server.networkPolicy() {
		return nil
	}
	return &udpSniffer{opt: im.sniff, targets: map[Address]*udpSniffState{}}
}

func (u *udpSniffer) timerC() <-chan time.Time {
	if u == nil || u.timer == nil {
		return nil
	}
	return u.timer.C
}

func (u *udpSniffer) packet(a *udpAssociation, p packet, idle time.Duration) {
	if !u.opt.udp.Contains(p.target.Port) {
		a.send(a.ctx, p, idle)
		return
	}
	now := time.Now()
	st := u.targets[p.target]
	if st != nil && st.res != nil {
		st.last = now
		a.send(withSniff(a.ctx, st.res), p, idle)
		return
	}
	if st == nil {
		// Only a client Initial starts sniffing: anything else (a QUIC
		// connection that predates the association, other UDP) is not held.
		if !sniff.IsInitial(p.payload) {
			a.send(a.ctx, p, idle)
			return
		}
		if len(u.targets) >= maxUDPSniffTargets {
			u.gc(now, idle)
		}
		if len(u.targets) >= maxUDPSniffTargets {
			a.send(a.ctx, p, idle)
			return
		}
		st = &udpSniffState{q: &sniff.QUIC{}, expires: now.Add(u.opt.Timeout.value()), last: now}
		u.targets[p.target] = st
	}
	st.last = now
	if sniff.IsInitial(p.payload) {
		host, status := st.q.Add(p.payload)
		switch status {
		case sniff.Done:
			u.decide(a, st, &sniffResult{proto: sniff.ProtoQUIC, host: host, override: u.opt.OverrideDestination}, p, idle)
			return
		case sniff.NeedMore:
			st.quic = true
		}
	}
	if len(st.held) >= maxHeldDatagrams || u.held+len(p.payload) > maxHeldBytes {
		u.decide(a, st, u.fallback(st), p, idle)
		return
	}
	st.held = append(st.held, p)
	u.held += len(p.payload)
	u.arm(now)
}

// fallback is the result when sniffing gives up on a target.
func (u *udpSniffer) fallback(st *udpSniffState) *sniffResult {
	if st.quic {
		return &sniffResult{proto: sniff.ProtoQUIC}
	}
	return &sniffResult{}
}

// decide fixes the target's result and sends the held datagrams, then p.
func (u *udpSniffer) decide(a *udpAssociation, st *udpSniffState, r *sniffResult, p packet, idle time.Duration) {
	st.res, st.q = r, nil
	held := st.held
	st.held = nil
	ctx := withSniff(a.ctx, r)
	for _, h := range held {
		u.held -= len(h.payload)
		a.send(ctx, h, idle)
	}
	if p.payload != nil {
		a.send(ctx, p, idle)
	}
}

// expire gives up sniffing on targets past their timeout.
func (u *udpSniffer) expire(a *udpAssociation, now time.Time, idle time.Duration) {
	u.timer = nil
	for _, st := range u.targets {
		if st.res == nil && !now.Before(st.expires) {
			u.decide(a, st, u.fallback(st), packet{}, idle)
		}
	}
	u.arm(now)
}

// arm (re)starts the timer for the earliest pending target.
func (u *udpSniffer) arm(now time.Time) {
	var next time.Time
	for _, st := range u.targets {
		if st.res == nil && (next.IsZero() || st.expires.Before(next)) {
			next = st.expires
		}
	}
	if next.IsZero() {
		if u.timer != nil {
			u.timer.Stop()
			u.timer = nil
		}
		return
	}
	if u.timer == nil {
		u.timer = time.NewTimer(next.Sub(now))
		return
	}
	u.timer.Reset(next.Sub(now))
}

// gc drops decided targets idle for longer than udp_idle.
func (u *udpSniffer) gc(now time.Time, idle time.Duration) {
	for k, st := range u.targets {
		if st.res != nil && now.Sub(st.last) > idle {
			delete(u.targets, k)
		}
	}
}

// sniffTCP sniffs a TCP stream before its destination is dialed. early, when
// not nil, is called before waiting for client data: protocols whose client
// waits for the server's reply (SOCKS5 CONNECT) are answered first. It
// returns the context carrying the result, the stream to relay from, the
// bytes already read (forward them right after the dial) and whether early
// was called. Without sniffing nothing changes and early is not called.
func (s *Server) sniffTCP(ctx context.Context, c net.Conn, target Address, early func() error) (context.Context, net.Conn, []byte, bool, error) {
	if s.sniffWanted(ctx, target.Port, false) == nil {
		return ctx, c, nil, false, nil
	}
	called := false
	if early != nil {
		if e := early(); e != nil {
			return ctx, c, nil, true, e
		}
		called = true
	}
	ctx, c, first := s.sniffStream(ctx, c, target)
	return ctx, c, first, called, nil
}
