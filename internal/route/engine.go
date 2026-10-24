package route

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Metadata describes one connection or datagram destination.
type Metadata struct {
	Network string     // tcp | udp
	Host    string     // lower-case domain name, or "" when IP is set
	IP      netip.Addr // valid when the destination is an IP literal
	Port    uint16
	Source  netip.Addr // client address
}

// Kind is the routing outcome class.
type Kind uint8

const (
	Direct Kind = iota
	Reject
	Proxy
)

func (k Kind) String() string {
	switch k {
	case Direct:
		return "direct"
	case Reject:
		return "reject"
	case Proxy:
		return "proxy"
	}
	return "unknown"
}

// Decision is the result of Decide.
type Decision struct {
	Kind       Kind
	Outbound   string       // Kind==Proxy: outbound or group name; the original Host is handed to it
	Candidates []netip.Addr // Kind==Direct: allowed IPs in resolver order; an IP target is itself
}

// Resolver resolves a domain name for IP rules and direct dialing.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DialFunc is the DialContext used for downloads through a via outbound.
type DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

const maxCandidates = 16

// Entry limits (variables only so tests can exercise them cheaply).
var (
	setEntryLimit   = maxSetEntries
	totalEntryLimit = maxTotalEntries
)

type verdict struct {
	kind Kind
	out  string
}

type matchKind uint8

const (
	mDomain matchKind = iota
	mSuffix
	mKeyword
	mIPCIDR
	mSrcIPCIDR
	mGeoIP
	mPort
	mNetwork
	mRuleSet
)

type compiledRule struct {
	kind      matchKind
	s         string
	prefix    netip.Prefix
	lo, hi    uint16
	set       *ruleSet
	noResolve bool
	v         verdict
}

type ruleSet struct {
	src  *source
	data atomic.Pointer[setData]
}

type geoSource struct {
	src *source
	db  atomic.Pointer[geoDB]
}

// Engine evaluates rules. Decide is safe for concurrent use, including while
// rule sets and the GeoIP database are being replaced in the background.
type Engine struct {
	rules   []compiledRule
	final   verdict
	sets    []*ruleSet
	geo     *geoSource // nil when no geoip block
	sources []*source
	dial    func(via string) (DialFunc, error)
	events  outbound.EventSink

	mu sync.Mutex // serializes data replacement (total entry accounting, file writes)

	life    sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Unexported test hooks.
	rootCAs      *x509.CertPool // nil = system roots
	backoffBase  time.Duration
	fetchTimeout time.Duration
	now          func() time.Time
}

func toVerdict(action, out string) verdict {
	switch {
	case action == "direct" || out == "direct":
		return verdict{kind: Direct}
	case action == "reject" || out == "reject":
		return verdict{kind: Reject}
	}
	return verdict{kind: Proxy, out: out}
}

// NewEngine validates o (on a copy), loads existing local rule-set and GeoIP
// files and never blocks on downloads. A missing or invalid local file starts
// that source empty and emits a *_update_failed event. dial maps a via name to
// the DialContext used for downloads; it is required when any url is set.
func NewEngine(o Options, dial func(via string) (func(ctx context.Context, network, addr string) (net.Conn, error), error), events outbound.EventSink) (*Engine, error) {
	o.Rules = append([]Rule(nil), o.Rules...)
	o.RuleSets = append([]RuleSetOptions(nil), o.RuleSets...)
	if o.GeoIP != nil {
		g := *o.GeoIP
		o.GeoIP = &g
	}
	if e := o.Validate(); e != nil {
		return nil, e
	}
	e := &Engine{
		dial:         dial,
		events:       events,
		final:        toVerdict("", o.Final),
		backoffBase:  time.Minute,
		fetchTimeout: 60 * time.Second,
		now:          time.Now,
	}
	byName := map[string]*ruleSet{}
	for _, so := range o.RuleSets {
		if so.URL != "" && dial == nil {
			return nil, errf("rule set %q: url requires a dial function", so.Name)
		}
		rs := &ruleSet{}
		format := so.Format
		rs.src = &source{
			kind: "rule_set", name: so.Name, path: so.Path, url: so.URL, via: so.Via,
			maxBytes: so.MaxBytes, interval: so.Interval.Value(),
			parse: func(b []byte) (any, error) { return parseRuleSet(format, b, setEntryLimit) },
			check: func(v any) error {
				n := v.(*setData).entries
				for _, other := range e.sets {
					if other != rs {
						if d := other.data.Load(); d != nil {
							n += d.entries
						}
					}
				}
				if n > totalEntryLimit {
					return errLimit
				}
				return nil
			},
			swap: func(v any) {
				d := v.(*setData)
				rs.data.Store(d)
				e.events.Emit("rule_set_loaded", "name", so.Name, "entries", itoa(d.entries), "skipped", itoa(d.skipped))
			},
		}
		rs.data.Store(&setData{})
		e.sets = append(e.sets, rs)
		e.sources = append(e.sources, rs.src)
		byName[so.Name] = rs
	}
	if g := o.GeoIP; g != nil {
		if g.URL != "" && dial == nil {
			return nil, errf("geoip: url requires a dial function")
		}
		gs := &geoSource{}
		gs.src = &source{
			kind: "geoip", path: g.Path, url: g.URL, via: g.Via, maxBytes: g.MaxBytes, interval: g.Interval.Value(),
			parse: func(b []byte) (any, error) { return parseGeoIP(b) },
			check: func(any) error { return nil },
			swap: func(v any) {
				gs.db.Store(v.(*geoDB))
				e.events.Emit("geoip_loaded")
			},
		}
		e.geo = gs
		e.sources = append(e.sources, gs.src)
	}
	for _, r := range o.Rules {
		c := compiledRule{v: toVerdict(r.Action, r.Outbound), noResolve: r.NoResolve}
		switch {
		case r.Domain != "":
			c.kind, c.s = mDomain, r.Domain
		case r.DomainSuffix != "":
			c.kind, c.s = mSuffix, r.DomainSuffix
		case r.DomainKeyword != "":
			c.kind, c.s = mKeyword, r.DomainKeyword
		case r.IPCIDR != "":
			c.kind = mIPCIDR
			c.prefix, _ = parseCIDR(r.IPCIDR, false)
		case r.SrcIPCIDR != "":
			c.kind = mSrcIPCIDR
			c.prefix, _ = parseCIDR(r.SrcIPCIDR, false)
		case r.GeoIP != "":
			c.kind, c.s = mGeoIP, r.GeoIP
		case r.DstPort != "":
			c.kind = mPort
			c.lo, c.hi, _ = parsePortRange(r.DstPort)
		case r.Network != "":
			c.kind, c.s = mNetwork, r.Network
		case r.RuleSet != "":
			c.kind, c.set = mRuleSet, byName[r.RuleSet]
		}
		e.rules = append(e.rules, c)
	}
	e.mu.Lock()
	for _, s := range e.sources {
		e.loadLocal(s)
	}
	e.mu.Unlock()
	return e, nil
}

// ---- Decide ----

// ipInfo memoizes the GeoIP country of one candidate during one evaluation.
type ipInfo struct {
	ip      netip.Addr
	geo     string
	geoDone bool
}

func (e *Engine) country(x *ipInfo) string {
	if !x.geoDone {
		x.geoDone = true
		if e.geo != nil {
			if db := e.geo.db.Load(); db != nil {
				x.geo = db.country(x.ip)
			}
		}
	}
	return x.geo
}

func (e *Engine) geoMatch(code string, x *ipInfo) bool {
	if code == geoPrivate {
		return isPrivate(x.ip)
	}
	return e.country(x) == code
}

// geoUsable reports whether a geoip condition can possibly match now.
func (e *Engine) geoUsable(code string) bool {
	return code == geoPrivate || e.geo != nil && e.geo.db.Load() != nil
}

type query struct {
	host    string
	port    uint16
	network string
	src     netip.Addr
}

// matchStatic evaluates the rule without a destination IP. For a rule set it
// is the domain/port part only.
func (r *compiledRule) matchStatic(q *query) bool {
	switch r.kind {
	case mDomain:
		return q.host != "" && q.host == r.s
	case mSuffix:
		return q.host != "" && (q.host == r.s || len(q.host) > len(r.s) && strings.HasSuffix(q.host, r.s) && q.host[len(q.host)-len(r.s)-1] == '.')
	case mKeyword:
		return q.host != "" && strings.Contains(q.host, r.s)
	case mSrcIPCIDR:
		return q.src.IsValid() && r.prefix.Contains(q.src)
	case mPort:
		return q.port >= r.lo && q.port <= r.hi
	case mNetwork:
		return q.network == r.s
	case mRuleSet:
		return r.set.data.Load().matchStatic(q.host, q.port)
	}
	return false
}

// needsIP reports whether a domain target must be resolved before this rule
// can be decided (IP condition without no_resolve that can match now).
func (e *Engine) needsIP(r *compiledRule) bool {
	if r.noResolve {
		return false
	}
	switch r.kind {
	case mIPCIDR:
		return true
	case mGeoIP:
		return e.geoUsable(r.s)
	case mRuleSet:
		d := r.set.data.Load()
		if !d.ip.empty() {
			return true
		}
		for _, c := range d.geo {
			if e.geoUsable(c) {
				return true
			}
		}
	}
	return false
}

// matchIP evaluates the IP part of the rule against a known destination IP.
func (e *Engine) matchIP(r *compiledRule, x *ipInfo) bool {
	switch r.kind {
	case mIPCIDR:
		return r.prefix.Contains(x.ip)
	case mGeoIP:
		return e.geoMatch(r.s, x)
	case mRuleSet:
		d := r.set.data.Load()
		if d.ip.contains(x.ip) || d.ipNR.contains(x.ip) {
			return true
		}
		for _, c := range d.geo {
			if e.geoMatch(c, x) {
				return true
			}
		}
		for _, c := range d.geoNR {
			if e.geoMatch(c, x) {
				return true
			}
		}
	}
	return false
}

// eval is ordered first match from rule index start; x == nil means no IP is
// available (IP conditions do not match).
func (e *Engine) eval(q *query, start int, x *ipInfo) verdict {
	for i := start; i < len(e.rules); i++ {
		r := &e.rules[i]
		if r.matchStatic(q) || x != nil && e.matchIP(r, x) {
			return r.v
		}
	}
	return e.final
}

// preDNS evaluates a domain target until the first rule that needs an IP.
// It returns the verdict and -1, or the index of that rule.
func (e *Engine) preDNS(q *query) (verdict, int) {
	for i := range e.rules {
		r := &e.rules[i]
		if r.matchStatic(q) {
			return r.v, -1
		}
		if e.needsIP(r) {
			return verdict{}, i
		}
	}
	return e.final, -1
}

func (e *Engine) lookup(ctx context.Context, resolve Resolver, host string) ([]netip.Addr, error) {
	if resolve == nil {
		return nil, errNoResolve
	}
	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) > maxCandidates {
		ips = ips[:maxCandidates]
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() || ip.Zone() != "" {
			continue
		}
		out = append(out, ip.Unmap())
	}
	if len(out) == 0 {
		return nil, ErrNoAddress
	}
	return out, nil
}

func dedupe(ips []netip.Addr) []netip.Addr {
	out := ips[:0:0]
	for _, ip := range ips {
		dup := false
		for _, o := range out {
			if o == ip {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, ip)
		}
	}
	return out
}

func toDecision(v verdict) Decision {
	if v.kind == Proxy {
		return Decision{Kind: Proxy, Outbound: v.out}
	}
	return Decision{Kind: v.kind}
}

// Decide routes one destination. See the README routing section for the full
// semantics; in short: ordered first match, domain rules before the first IP
// rule decide without DNS, otherwise one resolution and per-candidate first
// match where the first non-reject candidate decides.
func (e *Engine) Decide(ctx context.Context, m Metadata, resolve Resolver) (Decision, error) {
	q := query{port: m.Port, network: m.Network}
	if m.Source.IsValid() {
		q.src = m.Source.WithZone("").Unmap()
	}
	if m.IP.IsValid() {
		if m.IP.Zone() != "" {
			return Decision{Kind: Reject}, nil
		}
		ip := m.IP.Unmap()
		v := e.eval(&q, 0, &ipInfo{ip: ip})
		d := toDecision(v)
		if v.kind == Direct {
			d.Candidates = []netip.Addr{ip}
		}
		return d, nil
	}
	q.host = strings.ToLower(strings.TrimSuffix(m.Host, "."))
	if q.host == "" {
		return Decision{Kind: Reject}, errors.New("route: empty destination")
	}
	v, stop := e.preDNS(&q)
	if stop < 0 {
		if v.kind != Direct {
			return toDecision(v), nil
		}
		ips, err := e.lookup(ctx, resolve, q.host)
		if err != nil {
			return Decision{Kind: Direct}, err
		}
		return Decision{Kind: Direct, Candidates: dedupe(ips)}, nil
	}
	ips, err := e.lookup(ctx, resolve, q.host)
	if err != nil {
		// IP conditions cannot match; a non-direct outcome still applies.
		v = e.eval(&q, stop, nil)
		if v.kind == Direct {
			return Decision{Kind: Direct}, err
		}
		return toDecision(v), nil
	}
	var first *verdict
	var direct []netip.Addr
	for _, ip := range ips {
		c := e.eval(&q, stop, &ipInfo{ip: ip})
		if c.kind == Reject {
			continue
		}
		if first == nil {
			first = &c
		}
		if c.kind == Direct {
			direct = append(direct, ip)
		}
	}
	switch {
	case first == nil:
		return Decision{Kind: Reject}, nil
	case first.kind == Direct:
		return Decision{Kind: Direct, Candidates: dedupe(direct)}, nil
	}
	return toDecision(*first), nil
}

// ---- lifecycle ----

// Start launches background refresh for sources with a url. It is a no-op
// when called again or after Close. Refresh stops when ctx ends or on Close.
func (e *Engine) Start(ctx context.Context) {
	e.life.Lock()
	defer e.life.Unlock()
	if e.started || e.closed {
		return
	}
	e.started = true
	ctx, e.cancel = context.WithCancel(ctx)
	for _, s := range e.sources {
		if s.url == "" {
			continue
		}
		delay := time.Duration(0)
		if !s.mtime.IsZero() {
			if age := e.now().Sub(s.mtime); age >= 0 && age < s.interval {
				delay = s.interval - age
			}
		}
		e.wg.Add(1)
		go e.run(ctx, s, delay)
	}
}

// Close stops background refresh and waits for it. In-memory data stays
// usable; Decide keeps working after Close.
func (e *Engine) Close() error {
	e.life.Lock()
	e.closed = true
	if e.cancel != nil {
		e.cancel()
	}
	e.life.Unlock()
	e.wg.Wait()
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }
