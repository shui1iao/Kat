package group

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Load-balance group.
//
// Health: a member is healthy unless its last probe failed or it has had
// max_failed_times (default 5) consecutive real failures (dial error, or data
// written and nothing read before the connection ended). Reaching the limit
// triggers a probe round at once; a successful probe or connection brings the
// member back. Probing is lazy by default (only while the group is used,
// results older than probe.interval are refreshed); lazy: false probes every
// interval from Start. When no member is healthy, all members are used.
//
// Destination key: the registrable domain (eTLD+1, public suffix list) of a
// domain target, the domain itself when it has none, or the IP literal.
//
// Strategies:
//   - round-robin: the next healthy member for every new connection (UDP:
//     for every new destination key of a session);
//   - consistent-hashing: rendezvous hashing of the destination key over the
//     healthy member names. A key always maps to the same member while the
//     member set and health are unchanged; removing (or losing the health of)
//     a member only moves the keys that mapped to it;
//   - sticky-sessions: source IP + destination key stays on one member for
//     sticky_ttl (default 10m, counted from the assignment); the first member
//     is chosen at random among the healthy ones; an unhealthy member is
//     replaced at once.
//
// A dial failure tries the next candidate (at most 3 members), as the other
// automatic groups do. UDP sessions dispatch datagrams per destination key:
// each key is pinned to one member for the session's life; the member
// sessions are opened on first use.
const (
	lbStickyCap   = 4096 // sticky-session entries per group
	lbRouteCap    = 1024 // destination keys remembered per UDP session
	lbMaxSubs     = 32   // member sessions per UDP session
	lbOpenTimeout = 15 * time.Second
	lbReadQueue   = 64
)

type stickyEntry struct {
	member  string
	expires time.Time
}

type lbState struct {
	rr     uint64
	sticky map[string]stickyEntry
}

func newLBState() *lbState { return &lbState{sticky: map[string]stickyEntry{}} }

// DestinationKey returns the load-balance key of a destination host.
func DestinationKey(host string) string {
	if _, e := netip.ParseAddr(host); e == nil {
		return host
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if k, e := publicsuffix.EffectiveTLDPlusOne(h); e == nil {
		return k
	}
	return h
}

func hrwScore(key, member string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write([]byte(member))
	x := h.Sum64()
	// splitmix64 finalizer: FNV alone is weak in the high bits.
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// lbUpLocked: healthy (see the package comment above).
func (g *autoGroup) lbUpLocked(i int) bool {
	s := g.st[i]
	return (!s.probed || s.probeOK) && s.consec < g.cfg.maxFailed
}

// lbOrderLocked returns the candidate members for one connection (at most
// maxAttempts). allowed restricts the members considered (nil = all).
func (g *autoGroup) lbOrderLocked(src netip.Addr, key string, udp bool, now time.Time, allowed func(int) bool) []int {
	var pool []int
	for _, up := range []bool{true, false} {
		for i := range g.st {
			if udp && !g.members[i].UDP() || allowed != nil && !allowed(i) {
				continue
			}
			if g.lbUpLocked(i) == up {
				pool = append(pool, i)
			}
		}
		if len(pool) > 0 {
			break // healthy members only; all members when none is healthy
		}
	}
	if len(pool) == 0 {
		return nil
	}
	order := make([]int, 0, len(pool))
	switch g.cfg.strategy {
	case StrategyRoundRobin:
		start := int(g.lb.rr % uint64(len(pool)))
		g.lb.rr++
		for k := range pool {
			order = append(order, pool[(start+k)%len(pool)])
		}
	case StrategyConsistentHashing:
		order = g.hrwOrder(pool, key)
	case StrategyStickySessions:
		skey := src.String() + "|" + key
		first := -1
		if e, ok := g.lb.sticky[skey]; ok && now.Before(e.expires) {
			for _, i := range pool {
				if g.cfg.members[i] == e.member && g.lbUpLocked(i) {
					first = i
				}
			}
		}
		if first < 0 {
			first = pool[rand.IntN(len(pool))]
			if len(g.lb.sticky) >= lbStickyCap {
				for k, e := range g.lb.sticky {
					if !now.Before(e.expires) {
						delete(g.lb.sticky, k)
					}
				}
				if len(g.lb.sticky) >= lbStickyCap {
					clear(g.lb.sticky)
				}
			}
			g.lb.sticky[skey] = stickyEntry{g.cfg.members[first], now.Add(g.cfg.stickyTTL)}
		}
		order = append(order, first)
		for _, i := range g.hrwOrder(pool, skey) {
			if i != first {
				order = append(order, i)
			}
		}
	}
	if len(order) > maxAttempts {
		order = order[:maxAttempts]
	}
	return order
}

func (g *autoGroup) hrwOrder(pool []int, key string) []int {
	type sc struct {
		i int
		s uint64
	}
	all := make([]sc, len(pool))
	for k, i := range pool {
		all[k] = sc{i, hrwScore(key, g.cfg.members[i])}
	}
	// partial selection sort: only the first maxAttempts are needed
	n := min(maxAttempts, len(all))
	out := make([]int, 0, n)
	for k := 0; k < n; k++ {
		best := k
		for j := k + 1; j < len(all); j++ {
			if all[j].s > all[best].s {
				best = j
			}
		}
		all[k], all[best] = all[best], all[k]
		out = append(out, all[k].i)
	}
	return out
}

// lbPick returns the candidates for one TCP connection or UDP destination.
func (g *autoGroup) lbPick(src netip.Addr, key string, udp bool, allowed func(int) bool) []int {
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	g.useLocked(now)
	c := g.lbOrderLocked(src, key, udp, now, allowed)
	if len(c) > 0 {
		g.cur = c[0]
	}
	return c
}

func (g *autoGroup) lbDialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	cands := g.lbPick(outbound.SourceFrom(ctx), DestinationKey(dst.Host), false, nil)
	if len(cands) == 0 {
		return nil, noMember(g.cfg.name, "TCP")
	}
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
			g.realFailure(i, dst.Host, false)
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("group %q: %w", g.cfg.name, ctx.Err())
	}
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", g.cfg.name, len(errs), errors.Join(errs...))
}

func (g *autoGroup) lbListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if !g.UDP() {
		return nil, noMember(g.cfg.name, "UDP")
	}
	g.mu.Lock()
	g.useLocked(g.clk.Now())
	g.unlock()
	p := &lbPacket{
		g: g, ctx: context.WithoutCancel(ctx), src: outbound.SourceFrom(ctx),
		subs: map[int]*lbSub{}, route: map[string]int{},
		in: make(chan lbDatagram, lbReadQueue), done: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	return p, nil
}

// ---- UDP dispatch ----

type lbDatagram struct {
	b      []byte
	src    outbound.Addr
	member int
}

type lbSub struct {
	i  int
	pc outbound.PacketConn
}

// lbPacket is one UDP session of a load-balance group. One writer and one
// reader may use it concurrently (the outbound.PacketConn contract).
type lbPacket struct {
	g   *autoGroup
	ctx context.Context // values only: opening member sessions later
	src netip.Addr

	mu         sync.Mutex
	closed     bool
	subs       map[int]*lbSub
	route      map[string]int
	rdl        time.Time
	readMember string
	wdl        time.Time
	wg         sync.WaitGroup

	in   chan lbDatagram
	done chan struct{}
	wake chan struct{}
	once sync.Once
}

// MemberFor reports the member the session uses for dst (assigning one when
// dst is new). The kernel uses it to attribute statistics per member.
func (p *lbPacket) MemberFor(dst outbound.Addr) string {
	i, ok := p.assign(DestinationKey(dst.Host))
	if !ok {
		return ""
	}
	return p.g.cfg.members[i]
}

// assign returns the member for key, choosing one when key is new.
func (p *lbPacket) assign(key string) (int, bool) {
	p.mu.Lock()
	if i, ok := p.route[key]; ok {
		p.mu.Unlock()
		return i, true
	}
	full := len(p.subs) >= lbMaxSubs
	open := map[int]bool{}
	for i := range p.subs {
		open[i] = true
	}
	p.mu.Unlock()
	var allowed func(int) bool
	if full {
		allowed = func(i int) bool { return open[i] }
	}
	c := p.g.lbPick(p.src, key, true, allowed)
	if len(c) == 0 {
		return 0, false
	}
	p.mu.Lock()
	if len(p.route) >= lbRouteCap {
		clear(p.route)
	}
	p.route[key] = c[0]
	p.mu.Unlock()
	return c[0], true
}

func (p *lbPacket) sub(i int) *lbSub {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.subs[i]
}

// openSub opens a member session for key, trying the next candidates when
// the assigned member fails.
func (p *lbPacket) openSub(key string, first int) (*lbSub, error) {
	tried := map[int]bool{}
	cands := []int{first}
	var errs []error
	for len(cands) > 0 {
		i := cands[0]
		cands = cands[1:]
		if tried[i] {
			continue
		}
		tried[i] = true
		if s := p.sub(i); s != nil {
			p.setRoute(key, i)
			return s, nil
		}
		ctx, cancel := context.WithTimeout(p.ctx, lbOpenTimeout)
		pc, err := p.g.members[i].ListenPacket(ctx)
		cancel()
		if err == nil {
			s := &lbSub{i: i, pc: pc}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				pc.Close()
				return nil, net.ErrClosed
			}
			if old := p.subs[i]; old != nil { // cannot happen with one writer; keep the first
				p.mu.Unlock()
				pc.Close()
				return old, nil
			}
			p.subs[i] = s
			p.route[key] = i
			p.wg.Add(1)
			p.mu.Unlock()
			go p.readLoop(s)
			return s, nil
		}
		errs = append(errs, err)
		p.g.realFailure(i, "", false)
		if len(errs) >= maxAttempts {
			break
		}
		if len(cands) == 0 {
			for _, c := range p.g.lbPick(p.src, key, true, func(j int) bool { return !tried[j] }) {
				cands = append(cands, c)
			}
		}
	}
	if len(errs) == 0 {
		return nil, noMember(p.g.cfg.name, "UDP")
	}
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", p.g.cfg.name, len(errs), errors.Join(errs...))
}

func (p *lbPacket) setRoute(key string, i int) {
	p.mu.Lock()
	p.route[key] = i
	p.mu.Unlock()
}

func (p *lbPacket) readLoop(s *lbSub) {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := s.pc.ReadFrom(buf)
		if err != nil {
			p.dropSub(s)
			return
		}
		p.g.realSuccess(s.i, src.Host, 0, false)
		d := lbDatagram{b: append([]byte(nil), buf[:n]...), src: src, member: s.i}
		select {
		case p.in <- d:
		case <-p.done:
			return
		}
	}
}

func (p *lbPacket) dropSub(s *lbSub) {
	p.mu.Lock()
	if p.subs[s.i] == s {
		delete(p.subs, s.i)
		for k, i := range p.route {
			if i == s.i {
				delete(p.route, k)
			}
		}
	}
	p.mu.Unlock()
	s.pc.Close()
}

func (p *lbPacket) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	key := DestinationKey(dst.Host)
	i, ok := p.assign(key)
	if !ok {
		return 0, noMember(p.g.cfg.name, "UDP")
	}
	s := p.sub(i)
	if s == nil {
		var err error
		if s, err = p.openSub(key, i); err != nil {
			return 0, err
		}
	}
	p.mu.Lock()
	wdl := p.wdl
	p.mu.Unlock()
	s.pc.SetWriteDeadline(wdl)
	n, err := s.pc.WriteTo(b, dst)
	if err != nil {
		if !isDeadline(err) {
			p.g.realFailure(s.i, dst.Host, false)
		}
		p.dropSub(s)
	}
	return n, err
}

func (p *lbPacket) ReadFrom(b []byte) (int, outbound.Addr, error) {
	for {
		p.mu.Lock()
		dl := p.rdl
		p.mu.Unlock()
		var timeout <-chan time.Time
		var t *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, outbound.Addr{}, os.ErrDeadlineExceeded
			}
			t = time.NewTimer(d)
			timeout = t.C
		}
		stop := func() {
			if t != nil {
				t.Stop()
			}
		}
		select {
		case d := <-p.in:
			p.mu.Lock()
			p.readMember = p.g.cfg.members[d.member]
			p.mu.Unlock()
			stop()
			return copy(b, d.b), d.src, nil
		case <-p.done:
			stop()
			return 0, outbound.Addr{}, net.ErrClosed
		case <-timeout:
			return 0, outbound.Addr{}, os.ErrDeadlineExceeded
		case <-p.wake:
			stop() // deadline changed: re-evaluate
		}
	}
}

// ReadMember is the member that supplied the most recent ReadFrom.
func (p *lbPacket) ReadMember() string { p.mu.Lock(); defer p.mu.Unlock(); return p.readMember }

func (p *lbPacket) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		subs := p.subs
		p.subs = map[int]*lbSub{}
		p.mu.Unlock()
		close(p.done)
		for _, s := range subs {
			s.pc.Close()
		}
		p.wg.Wait()
	})
	return nil
}

func (p *lbPacket) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.rdl = t
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}

func (p *lbPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.wdl = t
	p.mu.Unlock()
	return nil
}
