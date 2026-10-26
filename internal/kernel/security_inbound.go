package kernel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ---- inbound source security (0.7.0) ----
//
// Three checks run when a TCP connection is accepted, before any handshake
// budget is taken: a temporary ban of sources with repeated authentication
// failures, the per-inbound source CIDR lists and the per-source concurrent
// connection limit. IPv4 sources are counted per address, IPv6 sources per
// /64 prefix (one subscriber usually owns a whole /64). The ban table and
// the connection counts belong to the process: they survive a reload and
// are empty after a restart.

// AuthBanOptions is "security.auth_ban". Omitted or enabled=false: off.
type AuthBanOptions struct {
	Enabled   bool     `json:"enabled"`
	Threshold int      `json:"threshold,omitempty"` // failures within window that ban, default 30
	Window    Duration `json:"window,omitempty"`    // counting window, default 1m
	Duration  Duration `json:"duration,omitempty"`  // ban length, default 10m
}

// SourceOptions is the per-inbound "sources" block. A source matching deny
// is refused; with a non-empty allow list only matching sources are
// accepted. Entries are IP addresses or CIDR prefixes.
type SourceOptions struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Defaults: generous enough for many users behind one NAT address (see the
// release notes), far below the rate of a password-guessing client.
const (
	defaultBanThreshold = 30
	defaultBanWindow    = time.Minute
	defaultBanDuration  = 10 * time.Minute
	maxSourceEntries    = 4096  // per inbound list
	maxTrackedSources   = 65536 // failure counters kept at once
	maxBannedSources    = 65536 // bans kept at once
	maxConnsPerSource   = 65536
	guardSweepInterval  = time.Second
)

func (c *Config) validateSecurity() error {
	// Loaders may return a shallow copy of an installed Config. Never
	// rewrite source lists or derived SOCKS5 options in that generation.
	c.Inbounds = append([]Inbound(nil), c.Inbounds...)
	if c.Security != nil {
		sec := *c.Security
		c.Security = &sec
		if sec.AuthBan != nil {
			ban := *sec.AuthBan
			sec.AuthBan = &ban
		}
	}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		if in.SOCKS5 != nil {
			o := *in.SOCKS5
			in.SOCKS5 = &o
			if o.Bind != nil {
				b := *o.Bind
				o.Bind = &b
			}
			if o.UDPFragment != nil {
				f := *o.UDPFragment
				o.UDPFragment = &f
			}
		}
	}
	if sec := c.Security; sec != nil {
		if b := sec.AuthBan; b != nil {
			if b.Threshold == 0 {
				b.Threshold = defaultBanThreshold
			}
			if b.Window == 0 {
				b.Window = Duration(defaultBanWindow)
			}
			if b.Duration == 0 {
				b.Duration = Duration(defaultBanDuration)
			}
			if b.Threshold < 1 || b.Threshold > 100000 {
				return errors.New("security.auth_ban.threshold must be between 1 and 100000")
			}
			if b.Window.value() < time.Second || b.Window.value() > 24*time.Hour || b.Duration.value() < time.Second || b.Duration.value() > 7*24*time.Hour {
				return errors.New("security.auth_ban.window must be 1s..24h and duration 1s..168h")
			}
		}
		if sec.MaxConnectionsPerIP < 0 || sec.MaxConnectionsPerIP > maxConnsPerSource {
			return errors.New("security.max_connections_per_ip must be between 0 (off) and 65536")
		}
	}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		in.srcAllow, in.srcDeny = nil, nil
		if o := in.Sources; o != nil {
			if len(o.Allow) > maxSourceEntries || len(o.Deny) > maxSourceEntries {
				return fmt.Errorf("inbound %d: sources.allow and sources.deny hold at most %d entries", i, maxSourceEntries)
			}
			var e error
			if in.srcAllow, e = parsePrefixes(o.Allow); e != nil {
				return fmt.Errorf("inbound %d: sources.allow: %v", i, e)
			}
			if in.srcDeny, e = parsePrefixes(o.Deny); e != nil {
				return fmt.Errorf("inbound %d: sources.deny: %v", i, e)
			}
		}
		if e := in.validateSOCKS5Options(c, i); e != nil {
			return e
		}
		if e := in.validateFallback(i); e != nil {
			return e
		}
	}
	l := &c.Limits
	if l.UDPFragmentBytes == 0 {
		l.UDPFragmentBytes = defaultFragmentTotal
	}
	if l.UDPFragmentBytes < 65535 || l.UDPFragmentBytes > 256<<20 {
		return errors.New("limits.udp_fragment_bytes must be between 65535 and 268435456")
	}
	return nil
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, e := netip.ParsePrefix(s); e == nil {
			if p.Addr().Zone() != "" || p.Bits() < unmapBits(p.Addr()) {
				return nil, fmt.Errorf("invalid prefix %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr()))
			out = append(out, p.Masked())
			continue
		}
		ip, e := netip.ParseAddr(s)
		if e != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("invalid address or prefix %q", s)
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// unmapBits is the number of prefix bits an IPv4-mapped IPv6 prefix loses
// when it is converted to IPv4.
func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

func matchAny(list []netip.Prefix, ip netip.Addr) bool {
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// sourceAllowed applies the inbound's CIDR lists (deny first).
func (in *Inbound) sourceAllowed(ip netip.Addr) bool {
	if len(in.srcDeny) == 0 && len(in.srcAllow) == 0 {
		return true
	}
	ip = ip.WithZone("").Unmap()
	if !ip.IsValid() || matchAny(in.srcDeny, ip) {
		return false
	}
	return len(in.srcAllow) == 0 || matchAny(in.srcAllow, ip)
}

func (c *Config) authBan() *AuthBanOptions {
	if c.Security == nil || c.Security.AuthBan == nil || !c.Security.AuthBan.Enabled {
		return nil
	}
	return c.Security.AuthBan
}

func (c *Config) perSourceLimit() int {
	if c.Security == nil {
		return 0
	}
	return c.Security.MaxConnectionsPerIP
}

// guardKey normalizes a client address to the unit counted by the guard.
func guardKey(ip netip.Addr) netip.Addr {
	ip = ip.WithZone("").Unmap()
	if ip.Is6() {
		if p, e := ip.Prefix(64); e == nil {
			return p.Addr()
		}
	}
	return ip
}

func guardKeyString(k netip.Addr) string {
	if k.Is6() {
		return k.String() + "/64"
	}
	return k.String()
}

// ParseBanKey accepts an IPv4 address, an IPv6 address or its /64 prefix.
func parseBanKey(s string) (netip.Addr, bool) {
	if p, e := netip.ParsePrefix(s); e == nil {
		if a := p.Addr().Unmap(); a.Is6() && p.Bits() == 64 {
			return guardKey(a), true
		} else if a.Is4() && p.Bits()-unmapBits(p.Addr()) == 32 {
			return a, true
		}
		return netip.Addr{}, false
	}
	ip, e := netip.ParseAddr(s)
	if e != nil {
		return netip.Addr{}, false
	}
	return guardKey(ip), true
}

type failWindow struct {
	start time.Time
	count int
}

type banEntry struct {
	since, until time.Time
	failures     int
	protocol     string
}

// sourceGuard is the process-wide ban table and per-source connection count.
type sourceGuard struct {
	k      *core
	mu     sync.Mutex
	fails  map[netip.Addr]*failWindow
	bans   map[netip.Addr]*banEntry
	conns  map[netip.Addr]int
	timer  *time.Timer // sweeps expired entries while any exist
	closed bool

	nbans atomic.Int64 // len(bans): the accept path skips the lock at 0

	authFailures  atomic.Int64
	bansTotal     atomic.Int64
	refusedBanned atomic.Int64
	refusedCIDR   atomic.Int64
	refusedLimit  atomic.Int64
	untracked     atomic.Int64 // failures not counted: tracking table full
}

func newSourceGuard(k *core) *sourceGuard {
	return &sourceGuard{k: k, fails: map[netip.Addr]*failWindow{}, bans: map[netip.Addr]*banEntry{}, conns: map[netip.Addr]int{}}
}

// banned reports whether ip is banned now.
func (g *sourceGuard) banned(ip netip.Addr, now time.Time) bool {
	if g == nil || g.nbans.Load() == 0 {
		return false
	}
	key := guardKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.bans[key]
	return b != nil && now.Before(b.until)
}

// acquireConn counts one connection of ip; false when limit (> 0) is reached.
func (g *sourceGuard) acquireConn(ip netip.Addr, limit int) bool {
	key := guardKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.conns[key]
	if limit > 0 && n >= limit {
		return false
	}
	g.conns[key] = n + 1
	return true
}

func (g *sourceGuard) releaseConn(ip netip.Addr) {
	if g == nil || !ip.IsValid() {
		return
	}
	key := guardKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	if n := g.conns[key]; n > 1 {
		g.conns[key] = n - 1
	} else {
		delete(g.conns, key)
	}
}

// authFailure records one authentication failure of ip under options o
// (nil = banning disabled: only counted).
func (g *sourceGuard) authFailure(ip netip.Addr, o *AuthBanOptions, protocol string, inbound int) {
	if g == nil || !ip.IsValid() {
		return
	}
	g.authFailures.Add(1)
	if o == nil {
		return
	}
	key := guardKey(ip)
	now := time.Now()
	g.mu.Lock()
	// A handshake accepted by an older generation can finish after banning
	// has been disabled. Do not repopulate the process-wide table then.
	cur := g.k.gen.Load()
	if g.closed || (cur != nil && cur.cfg.authBan() == nil) {
		g.mu.Unlock()
		return
	}
	if b := g.bans[key]; b != nil && now.Before(b.until) {
		g.mu.Unlock()
		return // a connection accepted just before the ban
	}
	w := g.fails[key]
	if w == nil || now.Sub(w.start) >= o.Window.value() {
		if w == nil {
			if len(g.fails) >= maxTrackedSources {
				g.sweepLocked(now)
			}
			if len(g.fails) >= maxTrackedSources {
				g.mu.Unlock()
				g.untracked.Add(1)
				return
			}
			w = &failWindow{}
			g.fails[key] = w
		}
		w.start, w.count = now, 0
	}
	w.count++
	if w.count < o.Threshold {
		g.armLocked()
		g.mu.Unlock()
		return
	}
	delete(g.fails, key)
	if len(g.bans) >= maxBannedSources {
		g.sweepLocked(now)
	}
	if len(g.bans) >= maxBannedSources {
		g.mu.Unlock()
		g.untracked.Add(1)
		return
	}
	if _, ok := g.bans[key]; !ok {
		g.nbans.Add(1)
	}
	g.bans[key] = &banEntry{since: now, until: now.Add(o.Duration.value()), failures: w.count, protocol: protocol}
	g.bansTotal.Add(1)
	g.armLocked()
	g.mu.Unlock()
	g.k.notice(levelWarn, "kat event=source_banned source="+truncateSource(key)+" protocol="+protocol+" inbound="+strconv.Itoa(inbound)+
		" failures="+strconv.Itoa(w.count)+" window="+o.Window.value().String()+" duration="+o.Duration.value().String())
}

// armLocked starts the sweep timer when entries exist and it is not running.
func (g *sourceGuard) armLocked() {
	if g.timer == nil && !g.closed && (len(g.fails) > 0 || len(g.bans) > 0) {
		g.timer = time.AfterFunc(guardSweepInterval, g.sweep)
	}
}

func (g *sourceGuard) sweep() {
	g.mu.Lock()
	g.timer = nil
	expired := g.sweepLocked(time.Now())
	g.armLocked()
	g.mu.Unlock()
	for _, k := range expired {
		g.k.notice(levelInfo, "kat event=source_ban_expired source="+truncateSource(k))
	}
}

// sweepLocked drops expired bans and failure windows (window lengths are
// those of the current configuration).
func (g *sourceGuard) sweepLocked(now time.Time) []netip.Addr {
	var expired []netip.Addr
	for k, b := range g.bans {
		if !now.Before(b.until) {
			delete(g.bans, k)
			g.nbans.Add(-1)
			expired = append(expired, k)
		}
	}
	window := defaultBanWindow
	if cur := g.k.gen.Load(); cur != nil {
		if o := cur.cfg.authBan(); o != nil {
			window = o.Window.value()
		}
	}
	for k, w := range g.fails {
		if now.Sub(w.start) >= window {
			delete(g.fails, k)
		}
	}
	return expired
}

// configure applies a new configuration: with banning disabled the table
// is emptied (nothing would enforce or expire it otherwise).
func (g *sourceGuard) configure(c *Config) {
	if c.authBan() != nil {
		return
	}
	g.mu.Lock()
	n := len(g.bans)
	clear(g.bans)
	clear(g.fails)
	g.nbans.Store(0)
	g.mu.Unlock()
	if n > 0 {
		g.k.notice(levelInfo, "kat event=source_bans_cleared reason=auth_ban_disabled count="+strconv.Itoa(n))
	}
}

func (g *sourceGuard) close() {
	g.mu.Lock()
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	g.mu.Unlock()
}

// BanInfo is one entry of GET /v1/bans.
type BanInfo struct {
	Source   string    `json:"source"`
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
	Failures int       `json:"failures"`
	Protocol string    `json:"protocol"`
}

func (g *sourceGuard) list() []BanInfo {
	now := time.Now()
	g.mu.Lock()
	out := make([]BanInfo, 0, len(g.bans))
	for k, b := range g.bans {
		if now.Before(b.until) {
			out = append(out, BanInfo{Source: guardKeyString(k), Since: b.since, Until: b.until, Failures: b.failures, Protocol: b.protocol})
		}
	}
	g.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// remove lifts the ban of source; false when it is not banned.
func (g *sourceGuard) remove(source string) (bool, error) {
	key, ok := parseBanKey(source)
	if !ok {
		return false, errors.New("source must be an IPv4 address, an IPv6 address or its /64 prefix")
	}
	now := time.Now()
	g.mu.Lock()
	b := g.bans[key]
	found := b != nil && now.Before(b.until)
	if b != nil {
		delete(g.bans, key)
		g.nbans.Add(-1)
	}
	delete(g.fails, key)
	g.mu.Unlock()
	if found {
		g.k.notice(levelInfo, "kat event=source_ban_removed source="+truncateSource(key))
	}
	return found, nil
}

// SecurityView is the "security" part of GET /v1/stats.
type SecurityView struct {
	AuthBanEnabled  bool  `json:"auth_ban_enabled"`
	Banned          int   `json:"banned"`
	BansTotal       int64 `json:"bans_since_start"`
	AuthFailures    int64 `json:"auth_failures"`
	RefusedBanned   int64 `json:"refused_banned"`
	RefusedSources  int64 `json:"refused_source_list"`
	RefusedPerIP    int64 `json:"refused_per_ip_limit"`
	TrackedSources  int   `json:"tracked_sources"`
	ConnectedSource int   `json:"connected_sources"`
	Untracked       int64 `json:"untracked_failures,omitempty"`
	FragmentBytes   int64 `json:"udp_fragment_bytes"`
	Reassembled     int64 `json:"udp_datagrams_reassembled"`
	FragmentDropped int64 `json:"udp_fragments_dropped"`
	BindActive      int64 `json:"socks5_bind_active"`
	TrojanFallbacks int64 `json:"trojan_fallbacks"`
}

func (k *core) securityView() SecurityView {
	g := k.guard
	now := time.Now()
	g.mu.Lock()
	banned := 0
	for _, b := range g.bans {
		if now.Before(b.until) {
			banned++
		}
	}
	v := SecurityView{Banned: banned, BansTotal: g.bansTotal.Load(), AuthFailures: g.authFailures.Load(), RefusedBanned: g.refusedBanned.Load(),
		RefusedSources: g.refusedCIDR.Load(), RefusedPerIP: g.refusedLimit.Load(), TrackedSources: len(g.fails), ConnectedSource: len(g.conns), Untracked: g.untracked.Load()}
	g.mu.Unlock()
	if cur := k.gen.Load(); cur != nil {
		v.AuthBanEnabled = cur.cfg.authBan() != nil
	}
	v.FragmentBytes = k.frags.used.Load()
	v.Reassembled = k.frags.reassembled.Load()
	v.FragmentDropped = k.frags.dropped.Load()
	v.BindActive = k.bindActive.Load()
	v.TrojanFallbacks = k.fallbacks.Load()
	return v
}

// screen applies the ban, the source lists and the per-source limit to an
// accepted connection of inbound in. On true the connection is counted for
// its source (released by releaseConn); on false it has been closed.
func (s *Server) screen(c net.Conn, in *Inbound) bool {
	ip := addrIP(c.RemoteAddr())
	g := s.guard
	refuse := func(k failureKind, n *atomic.Int64) bool {
		n.Add(1)
		s.failure(k, in.Protocol, in.logIndex)
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		c.Close()
		return false
	}
	if g.banned(ip, time.Now()) {
		return refuse(failSourceBanned, &g.refusedBanned)
	}
	if !in.sourceAllowed(ip) {
		return refuse(failSourceDenied, &g.refusedCIDR)
	}
	if !g.acquireConn(ip, s.cfg.perSourceLimit()) {
		return refuse(failSourceLimit, &g.refusedLimit)
	}
	return true
}

// udpSourceRefused applies the ban and the source lists to the first packet
// of a new UDP association (SS UDP inbounds).
func (s *Server) udpSourceRefused(ip netip.Addr, idx int) bool {
	if idx < 0 || idx >= len(s.cfg.Inbounds) {
		return false
	}
	g := s.guard
	if g.banned(ip, time.Now()) {
		g.refusedBanned.Add(1)
		return true
	}
	if !s.cfg.Inbounds[idx].sourceAllowed(ip) {
		g.refusedCIDR.Add(1)
		return true
	}
	return false
}

// authFailed records an authentication failure of the client of c.
func (s *Server) authFailed(src net.Addr, in *Inbound) {
	s.guard.authFailure(addrIP(src), s.cfg.authBan(), in.Protocol, in.logIndex)
}
