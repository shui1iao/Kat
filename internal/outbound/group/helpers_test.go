package group

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// ---- fake clock ----

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
	fired   bool
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped && !t.fired
		t.stopped = true
		return was
	}
}

// Advance moves time forward, firing due timers in time order; the clock
// reads each timer's deadline while its callback runs.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.stopped && !t.fired && !t.at.After(target) && (next == nil || t.at.Before(next.at)) {
				next = t
			}
		}
		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		next.fired = true
		if next.at.After(c.now) {
			c.now = next.at
		}
		c.mu.Unlock()
		next.f()
	}
}

func (c *fakeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped && !t.fired {
			n++
		}
	}
	return n
}

// ---- fake outbounds ----

// fakeConn is the client end of a net.Pipe tagged with the member that made it.
type fakeConn struct {
	net.Conn
	owner string
}

type fakeOut struct {
	name, typ string
	udp       bool

	mu      sync.Mutex
	dialErr error
	dials   int
	dsts    []outbound.Addr
	peers   chan net.Conn // server ends of successful dials
	onDial  func(ctx context.Context, dst outbound.Addr) (net.Conn, error)
	lpErr   error
	lps     int
	lastPC  *fakePC
}

func newFake(name string) *fakeOut {
	return &fakeOut{name: name, typ: "fake", udp: true, peers: make(chan net.Conn, 64)}
}

func (f *fakeOut) Name() string { return f.name }
func (f *fakeOut) Type() string { return f.typ }
func (f *fakeOut) Close() error { return nil }
func (f *fakeOut) UDP() bool    { return f.udp }

func (f *fakeOut) setErr(err error) {
	f.mu.Lock()
	f.dialErr = err
	f.mu.Unlock()
}

func (f *fakeOut) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

func (f *fakeOut) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	f.mu.Lock()
	f.dials++
	f.dsts = append(f.dsts, dst)
	err, hook := f.dialErr, f.onDial
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, dst)
	}
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	select {
	case f.peers <- b:
	default:
		b.Close()
	}
	return &fakeConn{Conn: a, owner: f.name}, nil
}

func (f *fakeOut) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lps++
	if !f.udp {
		return nil, outbound.ErrUDPUnsupported
	}
	if f.lpErr != nil {
		return nil, f.lpErr
	}
	f.lastPC = &fakePC{owner: f.name, in: make(chan []byte, 16), closed: make(chan struct{})}
	return f.lastPC, nil
}

type fakePC struct {
	owner  string
	in     chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	sent   int
}

func (p *fakePC) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	p.mu.Lock()
	p.sent++
	p.mu.Unlock()
	return len(b), nil
}
func (p *fakePC) ReadFrom(b []byte) (int, outbound.Addr, error) {
	select {
	case d := <-p.in:
		return copy(b, d), outbound.Addr{Host: "192.0.2.1", Port: 53}, nil
	case <-p.closed:
		return 0, outbound.Addr{}, net.ErrClosed
	}
}
func (p *fakePC) Close() error                     { p.once.Do(func() { close(p.closed) }); return nil }
func (p *fakePC) SetReadDeadline(time.Time) error  { return nil }
func (p *fakePC) SetWriteDeadline(time.Time) error { return nil }

// rejectOut mimics the kernel's built-in reject outbound.
type rejectOut struct{ name string }

func (r rejectOut) Name() string { return r.name }
func (r rejectOut) Type() string { return "reject" }
func (r rejectOut) Close() error { return nil }
func (r rejectOut) UDP() bool    { return true }
func (r rejectOut) DialTCP(context.Context, outbound.Addr) (net.Conn, error) {
	return nil, outbound.ErrRejected
}
func (r rejectOut) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrRejected
}

// loopOut dials for real (tests only ever point it at 127.0.0.1), like direct.
type loopOut struct {
	name  string
	delay time.Duration
	mu    sync.Mutex
	dsts  []outbound.Addr
	fail  bool
}

func (l *loopOut) Name() string { return l.name }
func (l *loopOut) Type() string { return "direct" }
func (l *loopOut) Close() error { return nil }
func (l *loopOut) UDP() bool    { return false }
func (l *loopOut) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	l.mu.Lock()
	l.dsts = append(l.dsts, dst)
	fail := l.fail
	l.mu.Unlock()
	if fail {
		return nil, errors.New("loopOut: down")
	}
	if l.delay > 0 {
		select {
		case <-time.After(l.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", dst.String())
}
func (l *loopOut) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (l *loopOut) targets() []outbound.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]outbound.Addr(nil), l.dsts...)
}

// ---- fake prober ----

type fakeProbe struct {
	mu    sync.Mutex
	lat   map[string]time.Duration
	fail  map[string]bool
	calls map[string]int
	block chan struct{} // when non-nil, probes wait for it
}

func newFakeProbe(lat map[string]time.Duration) *fakeProbe {
	return &fakeProbe{lat: lat, fail: map[string]bool{}, calls: map[string]int{}}
}

func (p *fakeProbe) set(name string, lat time.Duration, fail bool) {
	p.mu.Lock()
	p.lat[name], p.fail[name] = lat, fail
	p.mu.Unlock()
}

func (p *fakeProbe) count(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[name]
}

func (p *fakeProbe) fn(ctx context.Context, m outbound.Outbound) (time.Duration, error) {
	p.mu.Lock()
	block := p.block
	p.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[m.Name()]++
	if p.fail[m.Name()] {
		return 0, errors.New("fake probe failure")
	}
	return p.lat[m.Name()], nil
}

// ---- events ----

type eventLog struct {
	mu  sync.Mutex
	evs [][]string
}

func (l *eventLog) sink(event string, fields ...string) {
	l.mu.Lock()
	l.evs = append(l.evs, append([]string{event}, fields...))
	l.mu.Unlock()
}

func (l *eventLog) all() [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]string(nil), l.evs...)
}

// ---- helpers ----

func members(fs ...outbound.Outbound) []outbound.Outbound { return fs }

func names(fs []outbound.Outbound) []string {
	var n []string
	for _, f := range fs {
		n = append(n, f.Name())
	}
	return n
}

func probeOpts() *ProbeOptions { return &ProbeOptions{URL: "http://probe.test/generate_204"} }

func newAuto(t *testing.T, o Options, ms []outbound.Outbound, clk clock, p *fakeProbe, ev *eventLog) *autoGroup {
	t.Helper()
	if o.Members == nil {
		o.Members = names(ms)
	}
	if o.Probe == nil {
		o.Probe = probeOpts()
	}
	if o.Name == "" {
		o.Name = "g"
	}
	h := hooks{clk: clk}
	if p != nil {
		h.probe = p.fn
	}
	var sink outbound.EventSink
	if ev != nil {
		sink = ev.sink
	}
	g, err := newGroup(o, ms, sink, h)
	if err != nil {
		t.Fatalf("newGroup: %v", err)
	}
	ag := g.(*autoGroup)
	t.Cleanup(func() { ag.Close() })
	return ag
}

func waitRounds(t *testing.T, g *autoGroup, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for g.roundsRun.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d probe rounds (have %d)", n, g.roundsRun.Load())
		}
		time.Sleep(time.Millisecond)
	}
	// the round is applied before roundsRun is incremented
}

func isProbing(g *autoGroup) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.probing
}

// probeNow starts a round regardless of schedule (test helper).
func probeNow(t *testing.T, g *autoGroup) {
	t.Helper()
	n := g.roundsRun.Load()
	g.mu.Lock()
	g.triggerRoundLocked()
	g.unlock()
	waitRounds(t, g, n+1)
}

func ownerOf(c net.Conn) string {
	switch v := c.(type) {
	case *obsConn:
		return ownerOf(v.Conn)
	case obsConnCW:
		return ownerOf(v.Conn)
	case *fakeConn:
		return v.owner
	}
	return fmt.Sprintf("%T", c)
}

// dial dials through g and returns the member that carried the connection.
// The connection is closed (without traffic) unless keep is true.
func dial(t *testing.T, g outbound.Dialer, host string) string {
	t.Helper()
	c, err := g.DialTCP(context.Background(), outbound.Addr{Host: host, Port: 443})
	if err != nil {
		t.Fatalf("DialTCP(%s): %v", host, err)
	}
	defer c.Close()
	return ownerOf(c)
}

func switches(l *eventLog) []string {
	var out []string
	for _, e := range l.all() {
		if e[0] == "group_switch" {
			out = append(out, e[4]+">"+e[6])
		}
	}
	return out
}

func snapMember(g Snapshotter, name string) MemberSnapshot {
	for _, m := range g.Snapshot().Members {
		if m.Name == name {
			return m
		}
	}
	return MemberSnapshot{}
}

func sortedKeys(m map[string]int) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}
