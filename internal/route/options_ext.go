package route

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Rule-set formats. The text formats domain/ipcidr/classical keep their 0.6
// meaning (classical now covers every Kat rule type).
const (
	FormatDomain         = "domain"
	FormatIPCIDR         = "ipcidr"
	FormatClassical      = "classical"
	FormatYAML           = "yaml"             // Clash rule-provider payload; behavior required
	FormatMRS            = "mrs"              // mihomo binary; behavior domain|ipcidr
	FormatSRS            = "srs"              // sing-box binary rule set
	FormatSingBoxJSON    = "sing-box-json"    // sing-box source rule set
	FormatSurgeRuleSet   = "surge-ruleset"    // Surge RULE-SET (classical style)
	FormatSurgeDomainSet = "surge-domain-set" // Surge DOMAIN-SET
)

func validateFormat(s *RuleSetOptions) error {
	s.Behavior = strings.ToLower(s.Behavior)
	switch s.Format {
	case FormatDomain, FormatIPCIDR, FormatClassical, FormatSRS, FormatSingBoxJSON, FormatSurgeRuleSet, FormatSurgeDomainSet:
		if s.Behavior != "" {
			return errors.New("behavior is only used with format yaml or mrs")
		}
	case FormatYAML:
		switch s.Behavior {
		case "domain", "ipcidr", "classical":
		default:
			return errors.New("format yaml needs behavior domain, ipcidr or classical")
		}
	case FormatMRS:
		switch s.Behavior {
		case "domain", "ipcidr":
		default:
			return errors.New("format mrs needs behavior domain or ipcidr")
		}
	default:
		return errors.New("format must be domain, ipcidr, classical, yaml, mrs, srs, sing-box-json, surge-ruleset or surge-domain-set")
	}
	return nil
}

// cloneRule deep-copies the logical sub-conditions so that Validate's in-place
// normalization never touches the caller's slices.
func cloneRule(r Rule) Rule {
	if r.And != nil {
		l := make([]Rule, len(r.And))
		for i := range r.And {
			l[i] = cloneRule(r.And[i])
		}
		r.And = l
	}
	if r.Or != nil {
		l := make([]Rule, len(r.Or))
		for i := range r.Or {
			l[i] = cloneRule(r.Or[i])
		}
		r.Or = l
	}
	if r.Not != nil {
		n := cloneRule(*r.Not)
		r.Not = &n
	}
	return r
}

// parsePorts parses "80", "1000-2000" or a list of them separated by ',' or
// '/' (the classical-text separator), without spaces or empty items.
func parsePorts(s string) ([]portRange, bool) {
	if s == "" || len(s) > 1024 {
		return nil, false
	}
	var out []portRange
	for _, item := range strings.Split(strings.ReplaceAll(s, "/", ","), ",") {
		lo, hi, ok := parsePortRange(item)
		if !ok {
			return nil, false
		}
		out = append(out, portRange{lo, hi})
	}
	if len(out) == 0 || len(out) > 64 {
		return nil, false
	}
	return out, true
}

func portsString(ps []portRange) string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(p.lo)))
		if p.hi != p.lo {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(int(p.hi)))
		}
	}
	return b.String()
}

func normPorts(s string) (string, bool) {
	ps, ok := parsePorts(s)
	if !ok {
		return "", false
	}
	return portsString(ps), true
}

const maxRegexLen = 1024

// compileDomainRegex compiles an RE2 expression matched against the
// lower-case destination domain (no implicit anchors).
func compileDomainRegex(s string) (*regexp.Regexp, error) {
	if len(s) > maxRegexLen {
		return nil, errors.New("domain_regex too long")
	}
	re, e := regexp.Compile(s)
	if e != nil {
		return nil, fmt.Errorf("invalid domain_regex: %v", e)
	}
	return re, nil
}

// normWildcard accepts a domain pattern where '*' matches any run of
// characters (dots included) and '?' exactly one character.
func normWildcard(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if len(s) < 1 || len(s) > 253 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if !(c >= 'a' && c <= 'z' || s[i] >= '0' && s[i] <= '9' || s[i] == '-' || s[i] == '.' || s[i] == '_' || s[i] == '*' || s[i] == '?') {
			return "", false
		}
	}
	return strings.ToLower(s), true
}

// wildcardMatch: '*' any sequence (including empty and dots), '?' one byte.
func wildcardMatch(p, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(p) && (p[px] == '?' || p[px] == s[sx]):
			px++
			sx++
		case px < len(p) && p[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(p) && p[px] == '*' {
		px++
	}
	return px == len(p)
}

// normGeosite: category[@attr]... where an attribute may be negated with '!'.
// Lower case; v2fly category names use [a-z0-9-!_.].
func normGeosite(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 1 || len(s) > 128 {
		return "", false
	}
	parts := strings.Split(s, "@")
	for i, p := range parts {
		if p == "" || p == "!" {
			return "", false
		}
		for j := 0; j < len(p); j++ {
			c := p[j]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '!') {
				return "", false
			}
			if c == '!' && i > 0 && j > 0 {
				return "", false
			}
		}
	}
	return s, true
}

// parseIPSuffix parses ADDRESS/BITS: the rule matches addresses of the same
// family whose last BITS bits equal those of ADDRESS.
func parseIPSuffix(s string) (netip.Prefix, bool) {
	a, b, ok := strings.Cut(s, "/")
	if !ok {
		return netip.Prefix{}, false
	}
	ip, e := netip.ParseAddr(a)
	if e != nil || ip.Zone() != "" {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()
	n, e := strconv.Atoi(b)
	if e != nil || n < 0 || n > ip.BitLen() || strconv.Itoa(n) != b {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, n), true
}

func ipSuffixMatch(p netip.Prefix, ip netip.Addr) bool {
	a := p.Addr()
	if a.Is4() != ip.Is4() {
		return false
	}
	x, y := a.As16(), ip.As16()
	bits := p.Bits()
	for i := 15; i >= 0 && bits > 0; i-- {
		m := byte(0xff)
		if bits < 8 {
			m = byte(1)<<bits - 1
		}
		if x[i]&m != y[i]&m {
			return false
		}
		bits -= 8
	}
	return true
}

func parseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	if s == "" || len(s) > 10 {
		return 0, false
	}
	n, e := strconv.ParseUint(s, 10, 32)
	if e != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// normInType maps an inbound type name (Kat or mihomo spelling) to the Kat
// inbound protocol name.
func normInType(s string) (string, bool) {
	switch strings.ToLower(s) {
	case "shadowsocks", "ss":
		return "shadowsocks", true
	case "anytls":
		return "anytls", true
	case "trojan":
		return "trojan", true
	case "vless":
		return "vless", true
	case "socks5", "socks", "socks5h":
		return "socks5", true
	case "snell":
		return "snell", true
	}
	return "", false
}

// ReferencedInboundNames lists the in_name values used by rules (including
// logical sub-conditions). Call after Validate.
func (o *Options) ReferencedInboundNames() []string {
	var out []string
	var walk func(r *Rule)
	walk = func(r *Rule) {
		if r.InName != "" {
			out = append(out, r.InName)
		}
		for i := range r.And {
			walk(&r.And[i])
		}
		for i := range r.Or {
			walk(&r.Or[i])
		}
		if r.Not != nil {
			walk(r.Not)
		}
	}
	for i := range o.Rules {
		walk(&o.Rules[i])
	}
	return out
}

// PortList is a parsed port specification ("80,443,1000-2000").
type PortList []portRange

// ParsePorts parses a port, a range a-b or a list of them.
func ParsePorts(s string) (PortList, bool) {
	ps, ok := parsePorts(s)
	return PortList(ps), ok
}

// Contains reports whether p is in the list.
func (l PortList) Contains(p uint16) bool { return portIn(l, p) }
