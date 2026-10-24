// Package route implements Kat's rule engine: ordered first-match rules,
// text rule sets (domain / ipcidr / classical), a MaxMind DB country lookup and
// background HTTPS refresh of rule sets and the GeoIP database.
//
// The package is pure Go and portable. It never dials by itself: downloads go
// through the DialContext returned by the dial function injected into
// NewEngine, and DNS resolution for IP rules goes through the Resolver passed
// to Decide.
package route

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shui1iao/Kat/internal/outbound"
)

const (
	maxRules        = 1024
	maxRuleSets     = 32
	maxSetEntries   = 1_000_000
	maxTotalEntries = 2_000_000

	defaultInterval = 24 * time.Hour
	minInterval     = time.Minute

	defaultSetBytes = 16 << 20
	maxSetBytes     = 64 << 20
	defaultGeoBytes = 64 << 20
	maxGeoBytes     = 256 << 20
	minBytes        = 1 << 10

	maxNameLen = 64
	maxURLLen  = 2048
)

// Rule is one routing rule: exactly one match field plus exactly one of
// Action (direct|reject) or Outbound (outbound or group name).
type Rule struct {
	Domain        string `json:"domain,omitempty"`
	DomainSuffix  string `json:"domain_suffix,omitempty"`
	DomainKeyword string `json:"domain_keyword,omitempty"`
	IPCIDR        string `json:"ip_cidr,omitempty"`
	SrcIPCIDR     string `json:"src_ip_cidr,omitempty"`
	GeoIP         string `json:"geoip,omitempty"`
	DstPort       string `json:"dst_port,omitempty"`
	Network       string `json:"network,omitempty"`
	RuleSet       string `json:"rule_set,omitempty"`
	NoResolve     bool   `json:"no_resolve,omitempty"`
	Action        string `json:"action,omitempty"`
	Outbound      string `json:"outbound,omitempty"`
}

// RuleSetOptions describes one text rule set.
type RuleSetOptions struct {
	Name     string            `json:"name"`
	Format   string            `json:"format"`
	Path     string            `json:"path"`
	URL      string            `json:"url,omitempty"`
	Interval outbound.Duration `json:"interval,omitempty"`
	Via      string            `json:"via,omitempty"`
	MaxBytes int               `json:"max_bytes,omitempty"`
}

// GeoIPOptions describes the MaxMind DB country database.
type GeoIPOptions struct {
	Path     string            `json:"path"`
	URL      string            `json:"url,omitempty"`
	Interval outbound.Duration `json:"interval,omitempty"`
	Via      string            `json:"via,omitempty"`
	MaxBytes int               `json:"max_bytes,omitempty"`
}

// Options is the complete routing configuration.
type Options struct {
	Rules    []Rule           `json:"rules,omitempty"`
	Final    string           `json:"final,omitempty"`
	RuleSets []RuleSetOptions `json:"rule_sets,omitempty"`
	GeoIP    *GeoIPOptions    `json:"geoip,omitempty"`
}

func errf(format string, a ...any) error { return fmt.Errorf("route: "+format, a...) }

// Validate checks the options statically and normalizes them in place:
// domains are lowercased without trailing dot, geoip codes are upper case
// ("private" stays lower case), network is lower case, final defaults to
// "direct", rule-set/geoip interval defaults to 24h and via to "direct" when a
// url is set, max_bytes gets its default. A rule with outbound "direct" or
// "reject" is rewritten to the equivalent action. Whether referenced outbound
// names exist is NOT checked here (see ReferencedOutbounds).
func (o *Options) Validate() error {
	if len(o.Rules) > maxRules {
		return errf("too many rules (%d > %d)", len(o.Rules), maxRules)
	}
	if len(o.RuleSets) > maxRuleSets {
		return errf("too many rule sets (%d > %d)", len(o.RuleSets), maxRuleSets)
	}
	sets := map[string]bool{}
	paths := map[string]bool{}
	for i := range o.RuleSets {
		s := &o.RuleSets[i]
		if !validName(s.Name) {
			return errf("rule_sets[%d]: invalid name", i)
		}
		if sets[s.Name] {
			return errf("rule_sets[%d]: duplicate name %q", i, s.Name)
		}
		sets[s.Name] = true
		switch s.Format {
		case "domain", "ipcidr", "classical":
		default:
			return errf("rule set %q: format must be domain, ipcidr or classical", s.Name)
		}
		if e := validateSource(&s.Path, s.URL, &s.Interval, &s.Via, &s.MaxBytes, defaultSetBytes, maxSetBytes, paths); e != nil {
			return errf("rule set %q: %v", s.Name, e)
		}
	}
	if g := o.GeoIP; g != nil {
		if e := validateSource(&g.Path, g.URL, &g.Interval, &g.Via, &g.MaxBytes, defaultGeoBytes, maxGeoBytes, paths); e != nil {
			return errf("geoip: %v", e)
		}
	}
	for i := range o.Rules {
		if e := o.validateRule(&o.Rules[i], sets); e != nil {
			return errf("rules[%d]: %v", i, e)
		}
	}
	if o.Final == "" {
		o.Final = "direct"
	}
	if !validName(o.Final) {
		return errf("invalid final")
	}
	return nil
}

func (o *Options) validateRule(r *Rule, sets map[string]bool) error {
	n := 0
	for _, v := range []string{r.Domain, r.DomainSuffix, r.DomainKeyword, r.IPCIDR, r.SrcIPCIDR, r.GeoIP, r.DstPort, r.Network, r.RuleSet} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return errors.New("exactly one match field is required")
	}
	if (r.Action == "") == (r.Outbound == "") {
		return errors.New("exactly one of action or outbound is required")
	}
	if r.Action != "" && r.Action != "direct" && r.Action != "reject" {
		return errors.New("action must be direct or reject")
	}
	if r.Outbound != "" {
		if !validName(r.Outbound) {
			return errors.New("invalid outbound name")
		}
		if r.Outbound == "direct" || r.Outbound == "reject" {
			r.Action, r.Outbound = r.Outbound, ""
		}
	}
	if r.NoResolve && r.IPCIDR == "" && r.GeoIP == "" && r.RuleSet == "" {
		return errors.New("no_resolve is only allowed with ip_cidr, geoip or rule_set")
	}
	switch {
	case r.Domain != "":
		d, ok := normDomain(r.Domain)
		if !ok {
			return errors.New("invalid domain")
		}
		r.Domain = d
	case r.DomainSuffix != "":
		d, ok := normDomain(r.DomainSuffix)
		if !ok {
			return errors.New("invalid domain_suffix")
		}
		r.DomainSuffix = d
	case r.DomainKeyword != "":
		k, ok := normKeyword(r.DomainKeyword)
		if !ok {
			return errors.New("invalid domain_keyword")
		}
		r.DomainKeyword = k
	case r.IPCIDR != "":
		if _, ok := parseCIDR(r.IPCIDR, false); !ok {
			return errors.New("invalid ip_cidr")
		}
	case r.SrcIPCIDR != "":
		if _, ok := parseCIDR(r.SrcIPCIDR, false); !ok {
			return errors.New("invalid src_ip_cidr")
		}
	case r.GeoIP != "":
		c, ok := normGeo(r.GeoIP)
		if !ok {
			return errors.New("geoip must be a two-letter ISO country code or private")
		}
		r.GeoIP = c
		if c != geoPrivate && o.GeoIP == nil {
			return errors.New("geoip country rule requires a geoip block")
		}
	case r.DstPort != "":
		if _, _, ok := parsePortRange(r.DstPort); !ok {
			return errors.New("dst_port must be a port or a range a-b")
		}
	case r.Network != "":
		v := strings.ToLower(r.Network)
		if v != "tcp" && v != "udp" {
			return errors.New("network must be tcp or udp")
		}
		r.Network = v
	case r.RuleSet != "":
		if !sets[r.RuleSet] {
			return fmt.Errorf("undefined rule_set %q", r.RuleSet)
		}
	}
	return nil
}

func validateSource(path *string, rawURL string, interval *outbound.Duration, via *string, maxBytes *int, def, max int, paths map[string]bool) error {
	if *path == "" || strings.IndexByte(*path, 0) >= 0 {
		return errors.New("path is required")
	}
	clean := filepath.Clean(*path)
	if paths[clean] {
		return errors.New("path is shared with another source")
	}
	paths[clean] = true
	if *maxBytes == 0 {
		*maxBytes = def
	}
	if *maxBytes < minBytes || *maxBytes > max {
		return fmt.Errorf("max_bytes must be within [%d, %d]", minBytes, max)
	}
	if rawURL == "" {
		if *interval != 0 || *via != "" {
			return errors.New("interval and via require url")
		}
		return nil
	}
	if e := validateURL(rawURL); e != nil {
		return e
	}
	if *interval == 0 {
		*interval = outbound.Duration(defaultInterval)
	}
	if interval.Value() < minInterval {
		return errors.New("interval must be at least 1m")
	}
	if *via == "" {
		*via = "direct"
	}
	if !validName(*via) || *via == "reject" {
		return errors.New("invalid via")
	}
	return nil
}

// validateURL accepts only absolute https URLs without user info. Errors never
// echo the URL (it may carry tokens).
func validateURL(s string) error {
	if len(s) > maxURLLen {
		return errors.New("url too long")
	}
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" || u.Fragment != "" || strings.Contains(s, "#") {
		return errors.New("url must be an https URL without user info")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("url has an invalid port")
		}
	}
	return nil
}

// ReferencedOutbounds lists, in first-appearance order and without duplicates,
// every outbound/group name referenced by rules, final and rule-set/geoip via.
// The built-in names "direct" and "reject" are omitted. Call after Validate.
func (o *Options) ReferencedOutbounds() []string {
	var out []string
	seen := map[string]bool{"direct": true, "reject": true, "": true}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range o.Rules {
		add(r.Outbound)
	}
	add(o.Final)
	for _, s := range o.RuleSets {
		add(s.Via)
	}
	if o.GeoIP != nil {
		add(o.GeoIP.Via)
	}
	return out
}

func validName(s string) bool {
	if s == "" || len(s) > maxNameLen || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return false
		}
	}
	return true
}

// normDomain mirrors the kernel's dnsName: optional trailing dot, 1..253
// bytes, labels 1..63 of [A-Za-z0-9-] not starting/ending with '-'; result is
// lower case. It does not allocate when the input is already normalized.
func normDomain(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if len(s) < 1 || len(s) > 253 {
		return "", false
	}
	lower := true
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			l := s[start:i]
			if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
				return "", false
			}
			start = i + 1
			continue
		}
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		case c >= 'A' && c <= 'Z':
			lower = false
		default:
			return "", false
		}
	}
	if !lower {
		s = strings.ToLower(s)
	}
	return s, true
}

func normKeyword(s string) (string, bool) {
	if len(s) < 1 || len(s) > 253 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return "", false
		}
	}
	return strings.ToLower(s), true
}

const geoPrivate = "private"

func normGeo(s string) (string, bool) {
	if strings.EqualFold(s, geoPrivate) {
		return geoPrivate, true
	}
	if len(s) != 2 {
		return "", false
	}
	for i := 0; i < 2; i++ {
		c := s[i] | 0x20
		if c < 'a' || c > 'z' {
			return "", false
		}
	}
	return strings.ToUpper(s), true
}

// parseCIDR parses a prefix (or, when bare is set, a single IP) and applies the
// kernel's normalization: canonical mapped-v4 prefixes (/96 and longer) become
// IPv4; broader IPv6 prefixes stay IPv6 and never match IPv4 candidates.
func parseCIDR(s string, bare bool) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(s)
	if e != nil {
		if !bare {
			return netip.Prefix{}, false
		}
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(ip, ip.BitLen())
	}
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

func parsePort(s string) (uint16, bool) {
	if len(s) < 1 || len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

func parsePortRange(s string) (lo, hi uint16, ok bool) {
	a, b, isRange := strings.Cut(s, "-")
	if lo, ok = parsePort(a); !ok {
		return 0, 0, false
	}
	if !isRange {
		return lo, lo, true
	}
	if hi, ok = parsePort(b); !ok || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}
