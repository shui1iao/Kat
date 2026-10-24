// Package group implements Kat's policy groups: select, url-test, fallback and
// smart. A group is itself an outbound.Outbound, so groups can be nested and
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
)

// Fixed parameters (design constants; not configurable).
const (
	maxMembers           = 64
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
}

// Options is one entry of the root "groups" array.
type Options struct {
	Name      string             `json:"name"`
	Type      string             `json:"type"`                // select | url-test | fallback | smart
	Members   []string           `json:"members"`             // 1..64, unique
	Selected  string             `json:"selected,omitempty"`  // select only
	Probe     *ProbeOptions      `json:"probe,omitempty"`     // required for url-test/fallback/smart, forbidden for select
	Tolerance outbound.Duration  `json:"tolerance,omitempty"` // url-test only, default 100ms
	Priority  map[string]float64 `json:"priority,omitempty"`  // smart only; member name -> (0, 100], default 1
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
	case TypeSelect, TypeURLTest, TypeFallback, TypeSmart:
	default:
		return fail("unknown type %q", o.Type)
	}
	if len(o.Members) == 0 || len(o.Members) > maxMembers {
		return fail("members must have 1..%d entries", maxMembers)
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
		if !ok {
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
	if o.Type == TypeSelect {
		if o.Probe != nil {
			return fail("probe is not valid for select groups")
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
	if o.Type == TypeURLTest {
		c.tolerance = o.Tolerance.Value()
		if c.tolerance == 0 {
			c.tolerance = defaultTolerance
		}
	}
	if o.Type == TypeSmart {
		c.priority = make([]float64, len(o.Members))
		for i := range c.priority {
			c.priority[i] = 1
		}
		for name, v := range o.Priority {
			i, ok := index[name]
			if !ok {
				return fail("priority refers to unknown member %q", name)
			}
			if math.IsNaN(v) || v <= 0 || v > maxPriority {
				return fail("priority for %q must be in (0, %d]", name, maxPriority)
			}
			c.priority[i] = v
		}
	}
	return c, nil
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
	if c.kind == TypeSelect {
		return &selectGroup{cfg: c, members: ms, events: events, sel: c.selected}, nil
	}
	if h.probe == nil {
		h.probe = (&httpProber{url: c.url, target: c.target, tls: h.tls, clk: h.clk}).probe
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
