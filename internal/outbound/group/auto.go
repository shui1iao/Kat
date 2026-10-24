package group

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// memberState is the per-member bookkeeping shared by the automatic groups.
type memberState struct {
	// last probe round
	probed   bool
	probeOK  bool
	probeLat time.Duration
	probeAt  time.Time

	consec    int         // consecutive real failures (fallback, smart)
	failTimes []time.Time // url-test: real failures of this member within the window

	// smart
	ewma      time.Duration
	hasEWMA   bool
	penalty   float64 // milliseconds at penaltyAt
	penaltyAt time.Time
}

// autoGroup implements url-test, fallback and smart.
type autoGroup struct {
	cfg     config
	members []outbound.Outbound
	events  outbound.EventSink
	clk     clock
	probe   probeFunc

	mu       sync.Mutex
	st       []memberState
	cur      int
	curSince time.Time
	cold     bool        // smart: no probe round has completed yet
	pending  [][2]string // switch events to emit after unlocking

	hasRound  bool
	lastRound time.Time
	probing   bool
	started   bool
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	stopCtx   func() bool
	lastUse   time.Time
	paused    bool        // smart: periodic probing paused for inactivity
	tickStop  func() bool // smart: pending periodic tick
	sites     *siteCache  // smart
	wg        sync.WaitGroup
	roundsRun atomic.Int64 // completed probe rounds (tests)
}

func newAutoGroup(c config, ms []outbound.Outbound, events outbound.EventSink, h hooks) *autoGroup {
	g := &autoGroup{
		cfg: c, members: ms, events: events, clk: h.clk, probe: h.probe,
		st: make([]memberState, len(ms)), cold: true,
	}
	g.curSince = g.clk.Now()
	if c.kind == TypeSmart {
		g.sites = newSiteCache(smartSiteCap)
	}
	return g
}

func (g *autoGroup) Name() string      { return g.cfg.name }
func (g *autoGroup) Type() string      { return g.cfg.kind }
func (g *autoGroup) Members() []string { return append([]string(nil), g.cfg.members...) }

func (g *autoGroup) UDP() bool {
	for _, m := range g.members {
		if m.UDP() {
			return true
		}
	}
	return false
}

func (g *autoGroup) Current() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg.members[g.cur]
}

// unlock releases g.mu and then emits queued switch events, so an event sink
// may call back into the group.
func (g *autoGroup) unlock() {
	ev := g.pending
	g.pending = nil
	g.mu.Unlock()
	for _, e := range ev {
		emitSwitch(g.events, g.cfg.name, e[0], e[1])
	}
}

func (g *autoGroup) switchToLocked(i int, now time.Time) {
	if i == g.cur {
		return
	}
	g.pending = append(g.pending, [2]string{g.cfg.members[g.cur], g.cfg.members[i]})
	g.cur, g.curSince = i, now
}

// ---- lifecycle and probe scheduling ----

// Start enables background probing. url-test and fallback probe lazily (only
// when the group is used and results are missing or older than the interval);
// smart probes immediately and then every interval while it is being used.
func (g *autoGroup) Start(ctx context.Context) {
	g.mu.Lock()
	defer g.unlock()
	if g.started || g.closed {
		return
	}
	g.started = true
	g.ctx, g.cancel = context.WithCancel(ctx)
	g.stopCtx = context.AfterFunc(g.ctx, g.stopTimers)
	if g.cfg.kind == TypeSmart {
		now := g.clk.Now()
		g.lastUse = now
		g.triggerRoundLocked()
		g.scheduleTickLocked()
	}
}

// Close stops probing and waits for in-flight probe rounds. Members and
// connections handed out earlier are not closed.
func (g *autoGroup) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	if g.stopCtx != nil {
		g.stopCtx() // Close stops the timers itself
	}
	if g.cancel != nil {
		g.cancel()
	}
	if g.tickStop != nil {
		g.tickStop()
		g.tickStop = nil
	}
	g.mu.Unlock()
	g.wg.Wait()
	return nil
}

func (g *autoGroup) stopTimers() {
	g.mu.Lock()
	if g.tickStop != nil {
		g.tickStop()
		g.tickStop = nil
	}
	g.mu.Unlock()
}

func (g *autoGroup) activeLocked() bool {
	return g.started && !g.closed && g.ctx.Err() == nil
}

func (g *autoGroup) triggerRoundLocked() {
	if !g.activeLocked() || g.probing {
		return
	}
	g.probing = true
	g.wg.Add(1)
	go g.runRound(g.ctx)
}

func (g *autoGroup) scheduleTickLocked() {
	if !g.activeLocked() {
		return
	}
	if g.tickStop != nil {
		g.tickStop()
	}
	g.tickStop = g.clk.AfterFunc(g.cfg.interval, g.tick)
}

// tick is the smart group's periodic probe. Probing pauses when the group has
// not been used for smartIdleFactor intervals and resumes on the next use.
func (g *autoGroup) tick() {
	g.mu.Lock()
	defer g.unlock()
	g.tickStop = nil
	if !g.activeLocked() {
		return
	}
	if g.clk.Now().Sub(g.lastUse) >= smartIdleFactor*g.cfg.interval {
		g.paused = true
		return
	}
	g.triggerRoundLocked()
	g.scheduleTickLocked()
}

// useLocked records that the group is selecting a member for traffic.
func (g *autoGroup) useLocked(now time.Time) {
	g.lastUse = now
	switch g.cfg.kind {
	case TypeURLTest, TypeFallback:
		if !g.hasRound || now.Sub(g.lastRound) >= g.cfg.interval {
			g.triggerRoundLocked()
		}
	case TypeSmart:
		if g.paused && g.activeLocked() {
			g.paused = false
			if !g.hasRound || now.Sub(g.lastRound) >= g.cfg.interval {
				g.triggerRoundLocked()
			}
			g.scheduleTickLocked()
		}
	}
}

type probeResult struct {
	lat time.Duration
	err error
}

func (g *autoGroup) runRound(ctx context.Context) {
	defer g.wg.Done()
	res := make([]probeResult, len(g.members))
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for i, m := range g.members {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			pctx, cancel := context.WithTimeout(ctx, g.cfg.timeout)
			lat, err := g.probe(pctx, m)
			cancel()
			res[i] = probeResult{lat, err}
		}()
	}
	wg.Wait()
	g.mu.Lock()
	g.probing = false
	if ctx.Err() == nil {
		now := g.clk.Now()
		g.hasRound, g.lastRound = true, now
		for i, r := range res {
			s := &g.st[i]
			s.probed, s.probeOK, s.probeAt, s.probeLat = true, r.err == nil, now, 0
			if r.err == nil {
				s.probeLat = r.lat
			}
			switch g.cfg.kind {
			case TypeFallback:
				if r.err == nil {
					s.consec = 0 // a successful probe brings the member back
				}
			case TypeSmart:
				if r.err == nil {
					g.smartSuccessLocked(i, r.lat, true, now)
				} else {
					g.smartFailLocked(i, now)
				}
			}
		}
		g.reevaluateLocked(now)
	}
	g.unlock()
	g.roundsRun.Add(1)
}

// ---- selection ----

// reevaluateLocked recomputes the group-level current member.
func (g *autoGroup) reevaluateLocked(now time.Time) {
	switch g.cfg.kind {
	case TypeURLTest:
		g.urlTestReevalLocked(now)
	case TypeFallback:
		g.switchToLocked(g.fallbackPickLocked(), now)
	case TypeSmart:
		g.smartReevalLocked(now)
	}
}

// url-test: switch only when the current member failed its last probe, or the
// best member is faster by more than the tolerance. If every probe failed the
// current member is kept.
func (g *autoGroup) urlTestReevalLocked(now time.Time) {
	best := -1
	for i, s := range g.st {
		if s.probeOK && (best < 0 || s.probeLat < g.st[best].probeLat) {
			best = i
		}
	}
	if best < 0 {
		return
	}
	cur := g.st[g.cur]
	if !cur.probed || !cur.probeOK || cur.probeLat-g.st[best].probeLat > g.cfg.tolerance {
		g.switchToLocked(best, now)
	}
}

func (g *autoGroup) fallbackUpLocked(i int) bool {
	s := g.st[i]
	return (!s.probed || s.probeOK) && s.consec < fallbackFailLimit
}

// fallback: first member (in order) whose last probe succeeded (or that was
// not probed yet) and that has not failed fallbackFailLimit real connections
// in a row; the first member when none qualifies.
func (g *autoGroup) fallbackPickLocked() int {
	for i := range g.st {
		if g.fallbackUpLocked(i) {
			return i
		}
	}
	return 0
}

// candidatesLocked returns the member order for one connection (at most
// maxAttempts entries); udp restricts it to UDP-capable members.
func (g *autoGroup) candidatesLocked(host string, udp bool, now time.Time) []int {
	var order []int
	switch g.cfg.kind {
	case TypeURLTest:
		// current, then members with a successful probe by latency, then the rest in order
		order = append(order, g.cur)
		rest := make([]int, 0, len(g.st))
		for i := range g.st {
			if i != g.cur {
				rest = append(rest, i)
			}
		}
		sort.SliceStable(rest, func(a, b int) bool {
			sa, sb := g.st[rest[a]], g.st[rest[b]]
			if sa.probeOK != sb.probeOK {
				return sa.probeOK
			}
			return sa.probeOK && sa.probeLat < sb.probeLat
		})
		order = append(order, rest...)
	case TypeFallback:
		order = append(order, g.cur)
		for _, up := range []bool{true, false} {
			for i := range g.st {
				if i != g.cur && g.fallbackUpLocked(i) == up {
					order = append(order, i)
				}
			}
		}
	case TypeSmart:
		order = g.smartOrderLocked(host, now)
	}
	out := make([]int, 0, maxAttempts)
	for _, i := range order {
		if udp && !g.members[i].UDP() {
			continue
		}
		out = append(out, i)
		if len(out) == maxAttempts {
			break
		}
	}
	return out
}

// ---- traffic ----

// DialTCP dials through the selected member. When a member's dial fails (no
// client data has been sent yet) the next candidate is tried, at most
// maxAttempts members in total, within ctx. Failures after the connection is
// returned are reported to the caller and never retried.
func (g *autoGroup) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	g.mu.Lock()
	now := g.clk.Now()
	g.useLocked(now)
	g.reevaluateLocked(now)
	cands := g.candidatesLocked(dst.Host, false, now)
	g.unlock()
	var errs []error
	for _, i := range cands {
		if ctx.Err() != nil {
			break
		}
		c, err := g.members[i].DialTCP(ctx, dst)
		if err == nil {
			return wrapConn(c, g.newObserver(i, dst.Host)), nil
		}
		errs = append(errs, err)
		if !isCanceled(ctx) {
			g.realFailure(i, dst.Host, g.cfg.kind == TypeURLTest && serverRefused(g.members[i], err))
		}
	}
	if len(cands) == 0 {
		return nil, noMember(g.cfg.name, "TCP")
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("group %q: %w", g.cfg.name, ctx.Err())
	}
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", g.cfg.name, len(errs), errors.Join(errs...))
}

// ListenPacket picks among UDP-capable members only. The returned session
// stays on that member for its whole life.
func (g *autoGroup) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	g.mu.Lock()
	now := g.clk.Now()
	g.useLocked(now)
	g.reevaluateLocked(now)
	cands := g.candidatesLocked("", true, now)
	g.unlock()
	if len(cands) == 0 {
		return nil, noMember(g.cfg.name, "UDP")
	}
	var errs []error
	for _, i := range cands {
		if ctx.Err() != nil {
			break
		}
		pc, err := g.members[i].ListenPacket(ctx)
		if err == nil {
			if g.cfg.kind != TypeSmart {
				return pc, nil
			}
			return &obsPacket{PacketConn: pc, clk: g.clk, noReply: noReplyTimeout,
				report: func(ok bool) { g.udpResult(i, ok) }}, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("group %q: %w", g.cfg.name, ctx.Err())
	}
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", g.cfg.name, len(errs), errors.Join(errs...))
}

func (g *autoGroup) newObserver(i int, host string) *observer {
	o := &observer{clk: g.clk}
	if g.cfg.kind == TypeSmart {
		o.noReply = noReplyTimeout
	}
	o.report = func(ok bool, ttfb time.Duration, has bool) {
		if ok {
			g.realSuccess(i, host, ttfb, has)
		} else {
			g.realFailure(i, host, false)
		}
	}
	return o
}

// realFailure: a dial error, or data written and the connection closed/errored
// with zero bytes back (smart also: nothing back within 3 seconds).
// refused (url-test only) marks a dial error where the member's proxy server
// itself refused the TCP connection (see serverRefused): it triggers the
// re-test at once instead of after urlTestFailCount failures.
func (g *autoGroup) realFailure(i int, host string, refused bool) {
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	s := &g.st[i]
	switch g.cfg.kind {
	case TypeURLTest:
		if i != g.cur {
			return
		}
		kept := s.failTimes[:0]
		for _, t := range s.failTimes {
			if now.Sub(t) < urlTestFailWindow {
				kept = append(kept, t)
			}
		}
		s.failTimes = append(kept, now)
		if len(s.failTimes) >= urlTestFailCount || refused {
			s.failTimes = nil
			g.triggerRoundLocked()
		}
	case TypeFallback:
		s.consec++
		g.reevaluateLocked(now)
	case TypeSmart:
		g.smartFailLocked(i, now)
		if host != "" {
			g.sites.record(host, i, false, now)
		}
		g.reevaluateLocked(now)
	}
}

func (g *autoGroup) realSuccess(i int, host string, ttfb time.Duration, hasTTFB bool) {
	if g.cfg.kind == TypeURLTest {
		return
	}
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	switch g.cfg.kind {
	case TypeFallback:
		g.st[i].consec = 0
		g.reevaluateLocked(now)
	case TypeSmart:
		g.smartSuccessLocked(i, ttfb, hasTTFB, now)
		if host != "" {
			g.sites.record(host, i, true, now)
		}
		g.reevaluateLocked(now)
	}
}

func (g *autoGroup) udpResult(i int, ok bool) {
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	if ok {
		g.smartSuccessLocked(i, 0, false, now)
	} else {
		g.smartFailLocked(i, now)
	}
	g.reevaluateLocked(now)
}

// Snapshot reports per-member state without any destination information.
func (g *autoGroup) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.clk.Now()
	s := Snapshot{Name: g.cfg.name, Type: g.cfg.kind, Current: g.cfg.members[g.cur]}
	for i, st := range g.st {
		m := MemberSnapshot{
			Name: g.cfg.members[i], UDP: g.members[i].UDP(),
			Probed: st.probed, ProbeOK: st.probeOK, ProbeLatency: st.probeLat, ProbeAt: st.probeAt,
			Failures: st.consec,
		}
		switch g.cfg.kind {
		case TypeURLTest:
			m.Failures = 0
			for _, t := range st.failTimes {
				if now.Sub(t) < urlTestFailWindow {
					m.Failures++
				}
			}
		case TypeSmart:
			if st.hasEWMA {
				m.Latency = st.ewma
			}
			m.Penalty = msDur(g.penaltyLocked(i, now))
			m.Priority = g.cfg.priority[i]
			m.Score = msDur(g.scoreLocked(i, now))
		}
		s.Members = append(s.Members, m)
	}
	return s
}
