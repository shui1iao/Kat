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

	// Optional connection attributes (0.7.0): client source port, the
	// inbound that accepted the connection and the sniffing result.
	SrcPort   uint16
	InPort    uint16
	InName    string
	InType    string
	Protocol  string // sniffed: tls | http | quic
	SniffHost string // sniffed domain; used for domain rules when IP is set
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
	// Rule identifies the deciding rule for statistics: the 1-based index into
	// Options.Rules, 0 for final, -1 for a built-in refusal (zone/empty target).
	Rule int
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
	rule int // 1-based rule index, 0 = final
}

type compiledRule struct {
	c *cond
	v verdict
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
	geo     *geoSource  // nil when no geoip block
	asn     *asnSource  // nil when no asn block
	site    *siteSource // nil when no geosite block
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

// NewEngine validates o (on a copy), loads existing local rule-set, GeoIP,
// geosite and ASN files and never blocks on downloads. A missing or invalid
// local file starts that source empty and emits a *_update_failed event. dial
// maps a via name to the DialContext used for downloads; it is required when
// any url is set.
func NewEngine(o Options, dial func(via string) (func(ctx context.Context, network, addr string) (net.Conn, error), error), events outbound.EventSink) (*Engine, error) {
	o.Rules = append([]Rule(nil), o.Rules...)
	for i := range o.Rules {
		o.Rules[i] = cloneRule(o.Rules[i])
	}
	o.RuleSets = append([]RuleSetOptions(nil), o.RuleSets...)
	for _, p := range []**GeoIPOptions{&o.GeoIP, &o.Geosite, &o.ASN} {
		if *p != nil {
			g := **p
			*p = &g
		}
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
	env := parseEnv{geoip: o.GeoIP != nil, asn: o.ASN != nil, geosite: o.Geosite != nil}
	byName := map[string]*ruleSet{}
	for _, so := range o.RuleSets {
		if so.URL != "" && dial == nil {
			return nil, errf("rule set %q: url requires a dial function", so.Name)
		}
		rs := &ruleSet{}
		format, behavior := so.Format, so.Behavior
		rs.src = &source{
			kind: "rule_set", name: so.Name, path: so.Path, url: so.URL, via: so.Via,
			maxBytes: so.MaxBytes, interval: so.Interval.Value(),
			stamp: "rule_set|" + format + "|" + behavior + "|" + env.String(),
			parse: func(b []byte) (any, error) { return parseRuleSetAs(format, behavior, b, setEntryLimit, env) },
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
		rs.data.Store(&setData{mono: true})
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
			stamp: "geoip",
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
	if g := o.ASN; g != nil {
		if g.URL != "" && dial == nil {
			return nil, errf("asn: url requires a dial function")
		}
		as := &asnSource{}
		as.src = &source{
			kind: "asn", path: g.Path, url: g.URL, via: g.Via, maxBytes: g.MaxBytes, interval: g.Interval.Value(),
			stamp: "asn",
			parse: func(b []byte) (any, error) { return parseASNDB(b) },
			check: func(any) error { return nil },
			swap: func(v any) {
				as.db.Store(v.(*asnDB))
				e.events.Emit("asn_loaded")
			},
		}
		e.asn = as
		e.sources = append(e.sources, as.src)
	}
	if g := o.Geosite; g != nil {
		if g.URL != "" && dial == nil {
			return nil, errf("geosite: url requires a dial function")
		}
		refs := geositeRefs(o.Rules)
		ss := &siteSource{}
		ss.src = &source{
			kind: "geosite", path: g.Path, url: g.URL, via: g.Via, maxBytes: g.MaxBytes, interval: g.Interval.Value(),
			stamp: "geosite",
			parse: func(b []byte) (any, error) { return parseGeositeDB(b) },
			check: func(any) error { return nil },
			swap: func(v any) {
				db := v.(*siteDB)
				// Compile the categories the rules use now, outside Decide.
				missing := 0
				for _, r := range refs {
					if m := db.matcher(r); m == nil || m.missing {
						missing++
						e.events.Emit("geosite_category_missing", "category", r)
					}
				}
				ss.db.Store(db)
				e.events.Emit("geosite_loaded", "categories", itoa(len(db.index)), "missing", itoa(missing))
			},
		}
		e.site = ss
		e.sources = append(e.sources, ss.src)
	}
	for i := range o.Rules {
		r := &o.Rules[i]
		c := compiledRule{c: compileRule(r, byName), v: toVerdict(r.Action, r.Outbound)}
		c.v.rule = i + 1
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
	host     string
	port     uint16
	network  string
	src      netip.Addr
	srcPort  uint16
	inPort   uint16
	inName   string
	inType   string
	protocol string
	srcMemo  *ipInfo
}

func (q *query) srcInfo() *ipInfo {
	if q.srcMemo == nil {
		q.srcMemo = &ipInfo{ip: q.src}
	}
	return q.srcMemo
}

// eval is ordered first match from rule index start; x == nil means no IP is
// available (IP conditions do not match).
func (e *Engine) eval(q *query, start int, x *ipInfo) verdict {
	for i := start; i < len(e.rules); i++ {
		r := &e.rules[i]
		if e.match(r.c, q, x) {
			return r.v
		}
	}
	return e.final
}

// preDNS evaluates a domain target until the first rule that needs an IP.
// It returns the verdict and -1, or the index of that rule. A rule that needs
// an IP is still decided by its domain part when that cannot be undone by the
// IP (monotone), as for a rule set holding both domains and CIDRs.
func (e *Engine) preDNS(q *query) (verdict, int) {
	for i := range e.rules {
		switch e.tri(e.rules[i].c, q) {
		case triTrue:
			return e.rules[i].v, -1
		case triUnknown:
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
		return Decision{Kind: Proxy, Outbound: v.out, Rule: v.rule}
	}
	return Decision{Kind: v.kind, Rule: v.rule}
}

// Decide routes one destination. See the README routing section for the full
// semantics; in short: ordered first match, domain rules before the first IP
// rule decide without DNS, otherwise one resolution and per-candidate first
// match where the first non-reject candidate decides. For an IP destination a
// sniffed domain (SniffHost) is used by the domain conditions.
func (e *Engine) Decide(ctx context.Context, m Metadata, resolve Resolver) (Decision, error) {
	q := query{port: m.Port, network: m.Network, srcPort: m.SrcPort, inPort: m.InPort, inName: m.InName, inType: m.InType, protocol: m.Protocol}
	if m.Source.IsValid() {
		q.src = m.Source.WithZone("").Unmap()
	}
	if m.IP.IsValid() {
		if m.IP.Zone() != "" {
			return Decision{Kind: Reject, Rule: -1}, nil
		}
		if m.SniffHost != "" {
			if h, ok := normDomain(m.SniffHost); ok {
				q.host = h
			}
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
		return Decision{Kind: Reject, Rule: -1}, errors.New("route: empty destination")
	}
	v, stop := e.preDNS(&q)
	if stop < 0 {
		if v.kind != Direct {
			return toDecision(v), nil
		}
		ips, err := e.lookup(ctx, resolve, q.host)
		if err != nil {
			return Decision{Kind: Direct, Rule: v.rule}, err
		}
		return Decision{Kind: Direct, Candidates: dedupe(ips), Rule: v.rule}, nil
	}
	ips, err := e.lookup(ctx, resolve, q.host)
	if err != nil {
		// IP conditions cannot match; a non-direct outcome still applies.
		v = e.eval(&q, stop, nil)
		if v.kind == Direct {
			return Decision{Kind: Direct, Rule: v.rule}, err
		}
		return toDecision(v), nil
	}
	var first *verdict
	var direct []netip.Addr
	rejectRule := -1
	for _, ip := range ips {
		c := e.eval(&q, stop, &ipInfo{ip: ip})
		if c.kind == Reject {
			if rejectRule < 0 {
				rejectRule = c.rule
			}
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
		return Decision{Kind: Reject, Rule: rejectRule}, nil
	case first.kind == Direct:
		return Decision{Kind: Direct, Candidates: dedupe(direct), Rule: first.rule}, nil
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
