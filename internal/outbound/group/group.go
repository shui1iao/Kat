// Package group implements Kat's policy groups: select, url-test, fallback,
// smart and load-balance (relay groups are expanded by the kernel into via
// chains and never reach this package at run time). A group is itself an outbound.Outbound, so groups can be nested and
// used as the "via" hop of a protocol outbound.
//
// The smart group is Kat's own design. Its inputs and parameters were chosen
// after reading the public descriptions of similar features in other products,
// but it is not a reproduction of any of them; see smart.go for the exact,
// fully specified algorithm.
//
// All state is in memory only. Selection changes apply to new connections;
// established connections and UDP sessions keep the member they started with.
package group

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Group types.
const (
	TypeSelect   = "select"
	TypeURLTest  = "url-test"
	TypeFallback = "fallback"
	TypeSmart    = "smart"
	// TypeLoadBalance spreads connections over the healthy members.
	TypeLoadBalance = "load-balance"
	// TypeRelay chains its members (first = closest to Kat). The kernel turns
	// it into the equivalent via chain; New refuses it.
	TypeRelay = "relay"
)

// Load-balance strategies.
const (
	StrategyRoundRobin        = "round-robin"
	StrategyConsistentHashing = "consistent-hashing"
	StrategyStickySessions    = "sticky-sessions"
)

// Fixed parameters (design constants; not configurable).
const (
	maxMembers           = 64   // explicitly written members
	maxExpandedMembers   = 1024 // after provider/include_all expansion
	maxRelayMembers      = 4
	defaultStickyTTL     = 10 * time.Minute
	maxStickyTTL         = 24 * time.Hour
	maxFailedTimesLimit  = 100
	lbDefaultMaxFailed   = 5
	maxAttempts          = 3 // members tried per connection before giving up
	probeConcurrency     = 4
	defaultInterval      = 10 * time.Minute // url-test / fallback
	defaultSmartInterval = 5 * time.Minute
	minInterval          = time.Second
	defaultTimeout       = 5 * time.Second
	maxTimeout           = 60 * time.Second
	defaultTolerance     = 100 * time.Millisecond
	maxPriority          = 100

	urlTestFailWindow = 60 * time.Second // url-test: N real failures within this window ...
	urlTestFailCount  = 3                // ... trigger an immediate re-test
	fallbackFailLimit = 2                // fallback: consecutive real failures that mark a member down
	noReplyTimeout    = 3 * time.Second  // smart: data written / datagram sent but nothing came back
)

// ProbeOptions configures active HTTP(S) probing.
type ProbeOptions struct {
	URL      string            `json:"url"`                // required (http/https); no built-in default
	Interval outbound.Duration `json:"interval,omitempty"` // url-test/fallback default 10m; smart default 5m
	Timeout  outbound.Duration `json:"timeout,omitempty"`  // default 5s, max 60s
	// ExpectedStatus restricts the HTTP statuses that count as success:
	// "204", "200/204", "200-299/302" or "*". Empty = any status below 500.
	ExpectedStatus string `json:"expected_status,omitempty"`
}

// Options is one entry of the root "groups" array.
type Options struct {
	Name      string             `json:"name"`
	Type      string             `json:"type"`                // select | url-test | fallback | smart
	Members   []string           `json:"members,omitempty"`   // 1..64, unique
	Selected  string             `json:"selected,omitempty"`  // select only
	Probe     *ProbeOptions      `json:"probe,omitempty"`     // required for url-test/fallback/smart, forbidden for select
	Tolerance outbound.Duration  `json:"tolerance,omitempty"` // url-test only, default 100ms
	Priority  map[string]float64 `json:"priority,omitempty"`  // smart only; member name -> (0, 100], default 1

	// load-balance only.
	Strategy  string            `json:"strategy,omitempty"`   // round-robin | consistent-hashing (default) | sticky-sessions
	StickyTTL outbound.Duration `json:"sticky_ttl,omitempty"` // sticky-sessions, default 10m

	// Health checking (url-test, fallback, smart, load-balance).
	Lazy           *bool `json:"lazy,omitempty"`             // probe only while the group is used (default true; smart default: probe from start)
	MaxFailedTimes int   `json:"max_failed_times,omitempty"` // real failures that trigger a re-test / mark a member down

	// Dynamic members (expanded by the kernel; never valid for relay).
	Use                 []string `json:"use,omitempty"`    // provider names
	Filter              string   `json:"filter,omitempty"` // RE2 on member names; ` separates alternatives
	ExcludeFilter       string   `json:"exclude_filter,omitempty"`
	ExcludeType         string   `json:"exclude_type,omitempty"` // e.g. "shadowsocks|socks5"
	IncludeAll          bool     `json:"include_all,omitempty"`
	IncludeAllProxies   bool     `json:"include_all_proxies,omitempty"`
	IncludeAllProviders bool     `json:"include_all_providers,omitempty"`

	// Set by the kernel when Members holds the expanded member list.
	Expanded bool `json:"-"`
	// ConfigDefault is the configured default of an expanded select group:
	// selected, else the first written member, else "" (first available).
	ConfigDefault string `json:"-"`
}

// Dynamic reports whether the group takes members from providers or include_all*.
func (o Options) Dynamic() bool {
	return len(o.Use) > 0 || o.IncludeAll || o.IncludeAllProxies || o.IncludeAllProviders
}

// Group is a policy group. It is an outbound.Outbound itself.
type Group interface {
	outbound.Outbound
	// Members returns the member names in configuration order.
	Members() []string
	// Current returns the group-level choice (smart: the group's current
	// member; before any data: the first member).
	Current() string
	// Start starts background probing (lazy for url-test/fallback). Probing
	// stops when ctx ends or Close is called. Calling Start twice is a no-op.
	Start(ctx context.Context)
}

// Selector is implemented only by select groups (for a future GUI).
type Selector interface {
	Select(name string) error
}

// Snapshotter is implemented by every group returned by New.
type Snapshotter interface {
	Snapshot() Snapshot
}

// Snapshot is a point-in-time view of a group. It never contains destination
// or client addresses.
type Snapshot struct {
	Name    string
	Type    string
	Current string
	Members []MemberSnapshot
}

// MemberSnapshot describes one member. Fields not used by the group type are zero.
type MemberSnapshot struct {
	Name string
	UDP  bool
	// Last probe round result (url-test / fallback / smart).
	Probed       bool
	ProbeOK      bool
	ProbeLatency time.Duration
	ProbeAt      time.Time
	// Failures: url-test = real failures in the last 60s; fallback/smart =
	// consecutive real failures since the last success.
	Failures int
	// Smart only.
	Latency  time.Duration // EWMA of probe latency and first-response time; 0 = no sample yet
	Penalty  time.Duration // failure penalty decayed to the snapshot time
	Priority float64
	Score    time.Duration // (latency or probe timeout when unknown) + penalty, times priority
}

// Validate statically checks o. Member existence is checked by the kernel.
func Validate(o Options) error {
	_, err := normalize(o)
	return err
}

type config struct {
	name      string
	kind      string
	members   []string
	selected  int
	url       string
	target    outbound.Addr
	interval  time.Duration
	timeout   time.Duration
	tolerance time.Duration
	priority  []float64

	strategy  string
	stickyTTL time.Duration
	lazy      bool
	maxFailed int
	expected  func(int) bool // nil: status < 500
}

func normalize(o Options) (config, error) {
	var c config
	fail := func(format string, a ...any) (config, error) {
		return config{}, fmt.Errorf("group %q: "+format, append([]any{o.Name}, a...)...)
	}
	if strings.TrimSpace(o.Name) == "" {
		return fail("name is required")
	}
	switch o.Type {
	case TypeSelect, TypeURLTest, TypeFallback, TypeSmart, TypeLoadBalance:
	case TypeRelay:
		return normalizeRelay(o, fail)
	default:
		return fail("unknown type %q", o.Type)
	}
	dynamic := o.Dynamic()
	limit := maxMembers
	if o.Expanded {
		limit = maxExpandedMembers
	}
	if len(o.Members) > limit || (len(o.Members) == 0 && !dynamic) {
		if dynamic {
			return fail("members must have at most %d entries", limit)
		}
		return fail("members must have 1..%d entries", limit)
	}
	if _, err := memberFilter(o); err != nil {
		return fail("%v", err)
	}
	if !dynamic && (o.Filter != "" || o.ExcludeFilter != "" || o.ExcludeType != "") {
		return fail("filter, exclude_filter and exclude_type need use or include_all*")
	}
	seenUse := map[string]bool{}
	for _, u := range o.Use {
		if u == "" || seenUse[u] {
			return fail("empty or duplicate provider in use")
		}
		seenUse[u] = true
	}
	index := make(map[string]int, len(o.Members))
	for i, m := range o.Members {
		if m == "" {
			return fail("empty member name")
		}
		if m == o.Name {
			return fail("group cannot contain itself")
		}
		if _, dup := index[m]; dup {
			return fail("duplicate member %q", m)
		}
		if o.Type != TypeSelect && m == "reject" {
			return fail("%s group cannot contain reject", o.Type)
		}
		index[m] = i
	}
	c.name, c.kind, c.members = o.Name, o.Type, append([]string(nil), o.Members...)
	if o.Selected != "" {
		if o.Type != TypeSelect {
			return fail("selected is only valid for select groups")
		}
		i, ok := index[o.Selected]
		// A dynamic group may name a provider node that is resolved later.
		if !ok && (o.Expanded || !dynamic) {
			return fail("selected %q is not a member", o.Selected)
		}
		c.selected = i
	}
	if o.Tolerance != 0 && o.Type != TypeURLTest {
		return fail("tolerance is only valid for url-test groups")
	}
	if o.Tolerance < 0 {
		return fail("tolerance must not be negative")
	}
	if len(o.Priority) != 0 && o.Type != TypeSmart {
		return fail("priority is only valid for smart groups")
	}
	if (o.Strategy != "" || o.StickyTTL != 0) && o.Type != TypeLoadBalance {
		return fail("strategy and sticky_ttl are only valid for load-balance groups")
	}
	if o.Type == TypeSelect {
		if o.Probe != nil {
			return fail("probe is not valid for select groups")
		}
		if o.Lazy != nil || o.MaxFailedTimes != 0 {
			return fail("lazy and max_failed_times are not valid for select groups")
		}
		return c, nil
	}
	if o.Probe == nil {
		return fail("probe is required for %s groups", o.Type)
	}
	u, err := url.Parse(o.Probe.URL)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return fail("probe.url must be an absolute http or https URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fail("probe.url must be an absolute http or https URL")
	}
	host := strings.ToLower(u.Hostname())
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return fail("probe.url host must not have a zone")
		}
		host = ip.Unmap().String()
	}
	port := uint16(80)
	if scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || n == 0 {
			return fail("probe.url has an invalid port")
		}
		port = uint16(n)
	}
	c.url, c.target = o.Probe.URL, outbound.Addr{Host: host, Port: port}
	c.interval = o.Probe.Interval.Value()
	switch {
	case c.interval < 0 || (c.interval > 0 && c.interval < minInterval):
		return fail("probe.interval must be at least %s", minInterval)
	case c.interval == 0 && o.Type == TypeSmart:
		c.interval = defaultSmartInterval
	case c.interval == 0:
		c.interval = defaultInterval
	}
	c.timeout = o.Probe.Timeout.Value()
	switch {
	case c.timeout < 0 || c.timeout > maxTimeout:
		return fail("probe.timeout must be in (0, %s]", maxTimeout)
	case c.timeout == 0:
		c.timeout = defaultTimeout
	}
	if o.Probe.ExpectedStatus != "" {
		f, e := parseExpectedStatus(o.Probe.ExpectedStatus)
		if e != nil {
			return fail("probe.expected_status: %v", e)
		}
		c.expected = f
	}
	// lazy: url-test, fallback and load-balance default to probing only
	// while used (their previous behaviour); smart defaults to probing from
	// Start and pausing when idle.
	c.lazy = o.Type != TypeSmart
	if o.Lazy != nil {
		c.lazy = *o.Lazy
	}
	switch o.Type {
	case TypeURLTest:
		c.maxFailed = urlTestFailCount
	case TypeFallback:
		c.maxFailed = fallbackFailLimit
	case TypeLoadBalance:
		c.maxFailed = lbDefaultMaxFailed
	case TypeSmart:
		if o.MaxFailedTimes != 0 {
			return fail("max_failed_times is not valid for smart groups (fixed penalty model)")
		}
	}
	if o.MaxFailedTimes != 0 {
		if o.MaxFailedTimes < 1 || o.MaxFailedTimes > maxFailedTimesLimit {
			return fail("max_failed_times must be 1..%d", maxFailedTimesLimit)
		}
		c.maxFailed = o.MaxFailedTimes
	}
	if o.Type == TypeURLTest {
		c.tolerance = o.Tolerance.Value()
		if c.tolerance == 0 {
			c.tolerance = defaultTolerance
		}
	}
	if o.Type == TypeLoadBalance {
		c.strategy = o.Strategy
		switch c.strategy {
		case "":
			c.strategy = StrategyConsistentHashing
		case StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions:
		default:
			return fail("unknown strategy %q", o.Strategy)
		}
		if o.StickyTTL != 0 && c.strategy != StrategyStickySessions {
			return fail("sticky_ttl is only valid with strategy sticky-sessions")
		}
		c.stickyTTL = o.StickyTTL.Value()
		switch {
		case c.stickyTTL == 0:
			c.stickyTTL = defaultStickyTTL
		case c.stickyTTL < time.Second || c.stickyTTL > maxStickyTTL:
			return fail("sticky_ttl must be between 1s and %s", maxStickyTTL)
		}
	}
	if o.Type == TypeSmart {
		c.priority = make([]float64, len(o.Members))
		for i := range c.priority {
			c.priority[i] = 1
		}
		for name, v := range o.Priority {
			i, ok := index[name]
			if math.IsNaN(v) || v <= 0 || v > maxPriority {
				return fail("priority for %q must be in (0, %d]", name, maxPriority)
			}
			if !ok {
				if dynamic {
					continue // may name a provider node absent from this expansion
				}
				return fail("priority refers to unknown member %q", name)
			}
			c.priority[i] = v
		}
	}
	return c, nil
}

// normalizeRelay checks a relay group: 1..4 written members, nothing else.
func normalizeRelay(o Options, fail func(string, ...any) (config, error)) (config, error) {
	if o.Dynamic() || o.Filter != "" || o.ExcludeFilter != "" || o.ExcludeType != "" {
		return fail("relay members must be written explicitly (no use, filter or include_all*)")
	}
	if o.Selected != "" || o.Probe != nil || o.Tolerance != 0 || len(o.Priority) != 0 || o.Strategy != "" || o.StickyTTL != 0 || o.Lazy != nil || o.MaxFailedTimes != 0 {
		return fail("relay groups take only name, type and members")
	}
	if len(o.Members) == 0 || len(o.Members) > maxRelayMembers {
		return fail("relay members must have 1..%d entries", maxRelayMembers)
	}
	seen := map[string]bool{}
	for _, m := range o.Members {
		if m == "" || m == o.Name || seen[m] {
			return fail("empty, duplicate or self relay member")
		}
		if m == "direct" || m == "reject" {
			return fail("relay members must be outbounds or groups, not %s", m)
		}
		seen[m] = true
	}
	return config{name: o.Name, kind: TypeRelay, members: append([]string(nil), o.Members...)}, nil
}

// parseExpectedStatus parses "*", "204", "200/204" and ranges "200-299".
func parseExpectedStatus(s string) (func(int) bool, error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return func(int) bool { return true }, nil
	}
	type span struct{ lo, hi int }
	var spans []span
	for _, part := range strings.Split(s, "/") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, e1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var e2 error
		if isRange {
			b, e2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if e1 != nil || e2 != nil || a < 100 || b > 599 || a > b {
			return nil, fmt.Errorf("invalid status %q (use 204, 200/204, 200-299 or *)", part)
		}
		spans = append(spans, span{a, b})
		if len(spans) > 32 {
			return nil, errors.New("too many status entries")
		}
	}
	return func(code int) bool {
		for _, sp := range spans {
			if code >= sp.lo && code <= sp.hi {
				return true
			}
		}
		return false
	}, nil
}

// MemberFilter returns the predicate a dynamic member (name, Kat outbound
// type) must satisfy to join group o: filter (any alternative matches, when
// set), no exclude_filter alternative matches, type not in exclude_type.
// Written members are never filtered.
func MemberFilter(o Options) (func(name, typ string) bool, error) { return memberFilter(o) }

func memberFilter(o Options) (func(name, typ string) bool, error) {
	compile := func(field, s string) ([]*regexp.Regexp, error) {
		if s == "" {
			return nil, nil
		}
		var out []*regexp.Regexp
		for _, p := range strings.Split(s, "`") {
			if p == "" {
				continue
			}
			re, e := regexp.Compile(p)
			if e != nil {
				return nil, fmt.Errorf("%s: invalid regular expression %q (RE2 syntax; look-around is not supported)", field, p)
			}
			out = append(out, re)
		}
		return out, nil
	}
	inc, e := compile("filter", o.Filter)
	if e != nil {
		return nil, e
	}
	exc, e := compile("exclude_filter", o.ExcludeFilter)
	if e != nil {
		return nil, e
	}
	types := map[string]bool{}
	if o.ExcludeType != "" {
		for _, t := range strings.Split(o.ExcludeType, "|") {
			t = strings.ToLower(strings.TrimSpace(t))
			switch t {
			case "ss":
				t = "shadowsocks"
			case "socks":
				t = "socks5"
			}
			switch t {
			case "shadowsocks", "socks5", "trojan", "anytls":
			default:
				return nil, fmt.Errorf("exclude_type: unknown type %q (shadowsocks|ss, socks5|socks, trojan, anytls)", t)
			}
			types[t] = true
		}
	}
	return func(name, typ string) bool {
		if types[typ] {
			return false
		}
		for _, re := range exc {
			if re.MatchString(name) {
				return false
			}
		}
		if len(inc) == 0 {
			return true
		}
		for _, re := range inc {
			if re.MatchString(name) {
				return true
			}
		}
		return false
	}, nil
}

// New builds a group. members must be the resolved outbounds for o.Members,
// in the same order. New performs no network IO; probing starts with Start.
// Close does not close the members (they are owned by the caller).
func New(o Options, members []outbound.Outbound, events outbound.EventSink) (Group, error) {
	return newGroup(o, members, events, hooks{})
}

// hooks are package-internal injection points used by tests.
type hooks struct {
	clk   clock
	probe probeFunc   // replaces the HTTP prober
	tls   *tls.Config // base TLS config for https probes (tests inject a private root)
}

func newGroup(o Options, members []outbound.Outbound, events outbound.EventSink, h hooks) (Group, error) {
	c, err := normalize(o)
	if err != nil {
		return nil, err
	}
	if c.kind == TypeRelay {
		return nil, fmt.Errorf("group %q: relay groups are built by the kernel as via chains", c.name)
	}
	if len(members) != len(c.members) {
		return nil, fmt.Errorf("group %q: got %d member outbounds for %d member names", c.name, len(members), len(c.members))
	}
	for i, m := range members {
		if m == nil {
			return nil, fmt.Errorf("group %q: member %q is nil", c.name, c.members[i])
		}
		if m.Name() != c.members[i] {
			return nil, fmt.Errorf("group %q: member %d is %q, want %q", c.name, i, m.Name(), c.members[i])
		}
		if c.kind != TypeSelect && m.Type() == "reject" {
			return nil, fmt.Errorf("group %q: %s group cannot contain reject member %q", c.name, c.kind, c.members[i])
		}
	}
	ms := append([]outbound.Outbound(nil), members...)
	if h.clk == nil {
		h.clk = realClock{}
	}
	if len(ms) == 0 {
		// A dynamic group whose providers/filters currently yield nothing.
		return &emptyGroup{cfg: c}, nil
	}
	if c.kind == TypeSelect {
		return &selectGroup{cfg: c, members: ms, events: events, sel: c.selected}, nil
	}
	if h.probe == nil {
		h.probe = (&httpProber{url: c.url, target: c.target, tls: h.tls, clk: h.clk, expected: c.expected}).probe
	}
	return newAutoGroup(c, ms, events, h), nil
}

func emitSwitch(events outbound.EventSink, group, from, to string) {
	events.Emit("group_switch", "group", group, "from", from, "to", to)
}

func noMember(name, network string) error {
	return fmt.Errorf("group %q: no usable %s member: %w", name, network, outbound.ErrNoMember)
}

func isCanceled(ctx context.Context) bool { return errors.Is(ctx.Err(), context.Canceled) }

// clock abstracts time for tests.
type clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}
