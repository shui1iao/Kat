package group

import (
	"container/list"
	"math"
	"sort"
	"time"
)

// Smart group algorithm (Kat's own; all parameters fixed):
//
// Per member:
//   - latency: EWMA (alpha 0.3) over active probe latencies and real TCP
//     first-response times (first Write to first byte read). The first sample
//     initializes it. Members without a sample count as the probe timeout.
//   - failures: a dial error, data written then zero bytes before close/error,
//     nothing read within 3s after the first write, a failed probe, or a UDP
//     session with no datagram back within 3s of sending. The n-th consecutive
//     failure adds 300ms*2^(n-1) of penalty; the penalty is capped at 10s and
//     halves every 5 minutes. Any success (probe, first byte, UDP reply)
//     resets the consecutive count (the decaying penalty remains).
//   - score = (latency + penalty) * priority (default 1).
//
// Group-level current member (hysteresis):
//   - cold start: members in configuration order (first member current); the
//     first probe round starts immediately and when it completes the best
//     scored member becomes current without hysteresis;
//   - when the current member fails, switch at once to the best member that
//     has no consecutive failure (if any);
//   - otherwise switch only if the best member scores at least 20% and at
//     least 30ms better and the current member has been current for 60s.
//
// Per site (destination host name or IP literal), the most recent success and
// failure of each member is remembered for one hour in an LRU of 4096 sites.
// For a new connection: a member that recently succeeded for the site and is
// not more than 50% slower than the best usable member is preferred; else the
// group's current member, unless it recently failed for the site, in which
// case the best member that did not. Members that recently failed for the
// site go last in the retry order.
//
// Probing: immediately on Start, then every interval (default 5m); paused once
// the group has not been used for 5 intervals, resumed on the next use.
// Bandwidth is not considered. State is in memory only.
const (
	smartAlpha           = 0.3
	smartPenaltyBaseMS   = 300.0
	smartPenaltyCapMS    = 10000.0
	smartPenaltyHalfLife = 5 * time.Minute
	smartSwitchRatio     = 0.8 // candidate must be at least 20% better ...
	smartSwitchMinMS     = 30.0
	smartDwell           = 60 * time.Second
	smartSiteTTL         = time.Hour
	smartSiteCap         = 4096
	smartSiteSlack       = 1.5
	smartIdleFactor      = 5
)

func ms(d time.Duration) float64    { return float64(d) / float64(time.Millisecond) }
func msDur(v float64) time.Duration { return time.Duration(math.Round(v * float64(time.Millisecond))) }

func (g *autoGroup) smartSuccessLocked(i int, lat time.Duration, sample bool, now time.Time) {
	s := &g.st[i]
	s.consec = 0
	if !sample {
		return
	}
	if lat < 0 {
		lat = 0
	}
	if !s.hasEWMA {
		s.ewma, s.hasEWMA = lat, true
		return
	}
	s.ewma = time.Duration(math.Round(smartAlpha*float64(lat) + (1-smartAlpha)*float64(s.ewma)))
}

func (g *autoGroup) smartFailLocked(i int, now time.Time) {
	s := &g.st[i]
	s.consec++
	add := smartPenaltyCapMS
	if s.consec <= 16 {
		add = math.Min(smartPenaltyBaseMS*math.Pow(2, float64(s.consec-1)), smartPenaltyCapMS)
	}
	s.penalty = math.Min(g.penaltyLocked(i, now)+add, smartPenaltyCapMS)
	s.penaltyAt = now
}

// penaltyLocked returns member i's penalty (ms) decayed to now.
func (g *autoGroup) penaltyLocked(i int, now time.Time) float64 {
	s := g.st[i]
	if s.penalty == 0 {
		return 0
	}
	age := now.Sub(s.penaltyAt)
	if age <= 0 {
		return s.penalty
	}
	return s.penalty * math.Exp2(-float64(age)/float64(smartPenaltyHalfLife))
}

// scoreLocked returns member i's score in milliseconds (lower is better).
func (g *autoGroup) scoreLocked(i int, now time.Time) float64 {
	base := ms(g.cfg.timeout)
	if g.st[i].hasEWMA {
		base = ms(g.st[i].ewma)
	}
	return (base + g.penaltyLocked(i, now)) * g.cfg.priority[i]
}

// smartRankLocked orders members: no consecutive failure first, then by score,
// then by configuration order.
func (g *autoGroup) smartRankLocked(now time.Time) ([]int, []float64) {
	score := make([]float64, len(g.st))
	order := make([]int, len(g.st))
	for i := range g.st {
		score[i] = g.scoreLocked(i, now)
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		fa, fb := g.st[order[a]].consec > 0, g.st[order[b]].consec > 0
		if fa != fb {
			return !fa
		}
		return score[order[a]] < score[order[b]]
	})
	return order, score
}

func (g *autoGroup) smartReevalLocked(now time.Time) {
	order, score := g.smartRankLocked(now)
	cur := g.cur
	cs := g.st[cur]
	switch {
	case cs.consec > 0: // current failed: switch immediately
		for _, i := range order {
			if i != cur && g.st[i].consec == 0 {
				g.switchToLocked(i, now)
				return
			}
		}
		g.switchToLocked(order[0], now)
	case g.cold && !g.hasRound: // cold start: configuration order until the first round
	case g.cold: // first round done: take the best member without hysteresis
		g.cold = false
		g.switchToLocked(order[0], now)
	default:
		b := order[0]
		if b != cur && score[cur]-score[b] >= smartSwitchMinMS &&
			score[b] <= smartSwitchRatio*score[cur] && now.Sub(g.curSince) >= smartDwell {
			g.switchToLocked(b, now)
		}
	}
}

// smartOrderLocked returns the full member order for one connection to host.
func (g *autoGroup) smartOrderLocked(host string, now time.Time) []int {
	order, score := g.smartRankLocked(now)
	var site *siteEntry
	if host != "" {
		site = g.sites.get(host, now)
	}
	failed := func(i int) bool { return site != nil && site.failedRecently(i, now) }
	choice := -1
	if site != nil {
		best := math.Inf(1)
		for _, i := range order {
			if !failed(i) && g.st[i].consec == 0 && score[i] < best {
				best = score[i]
			}
		}
		for _, i := range order {
			if g.st[i].consec == 0 && site.succeededRecently(i, now) && score[i] <= smartSiteSlack*best {
				choice = i
				break
			}
		}
	}
	if choice < 0 {
		choice = g.cur
		if failed(choice) {
			for _, i := range order {
				if !failed(i) {
					choice = i
					break
				}
			}
		}
	}
	out := make([]int, 0, len(order))
	out = append(out, choice)
	for _, demoted := range []bool{false, true} {
		for _, i := range order {
			if i != choice && failed(i) == demoted {
				out = append(out, i)
			}
		}
	}
	return out
}

// ---- per-site memory ----

type siteRec struct {
	okAt, failAt time.Time
}

type siteEntry struct {
	key  string
	recs map[int]*siteRec
}

func (e *siteEntry) failedRecently(i int, now time.Time) bool {
	r := e.recs[i]
	return r != nil && !r.failAt.IsZero() && now.Sub(r.failAt) < smartSiteTTL && r.failAt.After(r.okAt)
}

func (e *siteEntry) succeededRecently(i int, now time.Time) bool {
	r := e.recs[i]
	return r != nil && !r.okAt.IsZero() && now.Sub(r.okAt) < smartSiteTTL && !r.failAt.After(r.okAt)
}

// siteCache is a bounded LRU of per-site member outcomes. Records older than
// smartSiteTTL are ignored and pruned lazily. It is never exported (it holds
// destination names).
type siteCache struct {
	cap int
	ll  *list.List
	m   map[string]*list.Element
}

func newSiteCache(n int) *siteCache {
	return &siteCache{cap: n, ll: list.New(), m: make(map[string]*list.Element)}
}

func (c *siteCache) get(key string, now time.Time) *siteEntry {
	el, ok := c.m[key]
	if !ok {
		return nil
	}
	e := el.Value.(*siteEntry)
	for i, r := range e.recs {
		if now.Sub(r.okAt) >= smartSiteTTL && now.Sub(r.failAt) >= smartSiteTTL {
			delete(e.recs, i)
		}
	}
	if len(e.recs) == 0 {
		c.ll.Remove(el)
		delete(c.m, key)
		return nil
	}
	c.ll.MoveToFront(el)
	return e
}

func (c *siteCache) record(key string, i int, ok bool, now time.Time) {
	var e *siteEntry
	if el, found := c.m[key]; found {
		e = el.Value.(*siteEntry)
		c.ll.MoveToFront(el)
	} else {
		e = &siteEntry{key: key, recs: make(map[int]*siteRec)}
		c.m[key] = c.ll.PushFront(e)
		for c.ll.Len() > c.cap {
			old := c.ll.Back()
			c.ll.Remove(old)
			delete(c.m, old.Value.(*siteEntry).key)
		}
	}
	r := e.recs[i]
	if r == nil {
		r = &siteRec{}
		e.recs[i] = r
	}
	if ok {
		r.okAt = now
	} else {
		r.failAt = now
	}
}

func (c *siteCache) len() int { return c.ll.Len() }
