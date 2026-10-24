package route

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"
)

var (
	errParse     = errors.New("route: content is not a valid rule set or database")
	errLimit     = errors.New("route: entry limit exceeded")
	errTooLarge  = errors.New("route: content exceeds max_bytes")
	errNoResolve = errors.New("route: no resolver")
	// ErrNoAddress is returned when the resolver succeeded but produced no
	// usable address for a destination that must be dialed directly.
	ErrNoAddress = errors.New("route: no address for destination")
)

// ---- IP ranges: sorted, merged, binary-searched; IPv4 and IPv6 separate ----

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }
func (a u128) inc() (u128, bool) { // a+1, overflow
	if a.lo != ^uint64(0) {
		return u128{a.hi, a.lo + 1}, false
	}
	if a.hi != ^uint64(0) {
		return u128{a.hi + 1, 0}, false
	}
	return u128{}, true
}
func addr128(ip netip.Addr) u128 {
	b := ip.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

type r4 struct{ lo, hi uint32 }
type r6 struct{ lo, hi u128 }

type ipSet struct {
	v4 []r4
	v6 []r6
}

func (s *ipSet) empty() bool { return len(s.v4) == 0 && len(s.v6) == 0 }

// add takes a masked, normalized prefix.
func (s *ipSet) add(p netip.Prefix) {
	ip := p.Addr()
	if ip.Is4() {
		b := ip.As4()
		lo := binary.BigEndian.Uint32(b[:])
		hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
		s.v4 = append(s.v4, r4{lo, hi})
		return
	}
	lo := addr128(ip)
	host := 128 - p.Bits()
	hi := lo
	switch {
	case host >= 64:
		hi.lo = ^uint64(0)
		hi.hi |= uint64(1)<<(host-64) - 1
		if host == 128 {
			hi.hi = ^uint64(0)
		}
	default:
		hi.lo |= uint64(1)<<host - 1
	}
	s.v6 = append(s.v6, r6{lo, hi})
}

func (s *ipSet) build() {
	slices.SortFunc(s.v4, func(a, b r4) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	out4 := s.v4[:0]
	for _, r := range s.v4 {
		if n := len(out4); n > 0 && (out4[n-1].hi == ^uint32(0) || r.lo <= out4[n-1].hi+1) {
			if r.hi > out4[n-1].hi {
				out4[n-1].hi = r.hi
			}
			continue
		}
		out4 = append(out4, r)
	}
	s.v4 = slices.Clip(out4)
	slices.SortFunc(s.v6, func(a, b r6) int {
		switch {
		case a.lo.less(b.lo):
			return -1
		case b.lo.less(a.lo):
			return 1
		}
		return 0
	})
	out6 := s.v6[:0]
	for _, r := range s.v6 {
		if n := len(out6); n > 0 {
			next, ovf := out6[n-1].hi.inc()
			if ovf || !next.less(r.lo) {
				if out6[n-1].hi.less(r.hi) {
					out6[n-1].hi = r.hi
				}
				continue
			}
		}
		out6 = append(out6, r)
	}
	s.v6 = slices.Clip(out6)
}

// contains expects an unmapped address without zone.
func (s *ipSet) contains(ip netip.Addr) bool {
	if ip.Is4() {
		b := ip.As4()
		x := binary.BigEndian.Uint32(b[:])
		lo, hi := 0, len(s.v4)
		for lo < hi { // first index with v4[i].lo > x
			m := int(uint(lo+hi) >> 1)
			if s.v4[m].lo <= x {
				lo = m + 1
			} else {
				hi = m
			}
		}
		return lo > 0 && x <= s.v4[lo-1].hi
	}
	if !ip.Is6() {
		return false
	}
	x := addr128(ip)
	lo, hi := 0, len(s.v6)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if !x.less(s.v6[m].lo) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo > 0 && !s.v6[lo-1].hi.less(x)
}

// ---- domains: exact and suffix maps (label-suffix walk), keywords linear ----

type domainSet struct {
	exact, suffix map[string]struct{}
	keywords      []string
}

func (d *domainSet) match(host string) bool {
	if host == "" {
		return false
	}
	if _, ok := d.exact[host]; ok {
		return true
	}
	if len(d.suffix) > 0 {
		for s := host; ; {
			if _, ok := d.suffix[s]; ok {
				return true
			}
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
		}
	}
	for _, k := range d.keywords {
		if strings.Contains(host, k) {
			return true
		}
	}
	return false
}

type portRange struct{ lo, hi uint16 }

func portIn(ps []portRange, p uint16) bool {
	for _, r := range ps {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

// setData is an immutable parsed rule set (swapped atomically on update).
type setData struct {
	dom   domainSet
	ports []portRange
	ip    ipSet    // IP entries that may trigger resolution
	ipNR  ipSet    // IP entries marked no-resolve (only match when an IP is known)
	geo   []string // GEOIP entries that may trigger resolution
	geoNR []string
	// entries/skipped are reported in rule_set_loaded.
	entries, skipped int
}

func (d *setData) matchStatic(host string, port uint16) bool {
	return d.dom.match(host) || portIn(d.ports, port)
}

// ---- parsing ----

// parseRuleSet parses a text rule set. Unsupported or malformed lines are
// skipped and counted; the whole content fails only when it is not text, has
// more than limit entries, or contains malformed lines and no valid entry.
func parseRuleSet(format string, b []byte, limit int) (*setData, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return nil, errParse
	}
	text := string(b) // one copy; accepted entries are substrings of it
	lines := strings.Count(text, "\n") + 1
	d := &setData{}
	hint := min(lines, limit)
	switch format {
	case "domain":
		d.dom.exact = make(map[string]struct{}, hint)
		d.dom.suffix = make(map[string]struct{}, hint/4)
	case "classical":
		d.dom.exact = map[string]struct{}{}
		d.dom.suffix = map[string]struct{}{}
	}
	bad := 0
	for len(text) > 0 {
		var line string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			line, text = text, ""
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue
		}
		var ok, unsupported bool
		switch format {
		case "domain":
			ok, unsupported = d.addDomainLine(line)
		case "ipcidr":
			var p netip.Prefix
			if p, ok = parseCIDR(line, true); ok {
				d.ip.add(p)
			}
		case "classical":
			ok, unsupported = d.addClassicalLine(line)
		default:
			return nil, errParse
		}
		switch {
		case ok:
			d.entries++
			if d.entries > limit {
				return nil, errLimit
			}
		case unsupported:
			d.skipped++
		default:
			d.skipped++
			bad++
		}
	}
	if d.entries == 0 && bad > 0 {
		return nil, errParse
	}
	d.ip.build()
	d.ipNR.build()
	return d, nil
}

func (d *setData) addDomainLine(s string) (ok, unsupported bool) {
	suffix := false
	switch {
	case strings.HasPrefix(s, "+."):
		suffix, s = true, s[2:]
	case strings.HasPrefix(s, "."):
		suffix, s = true, s[1:]
	case strings.HasPrefix(s, "*"):
		return false, true // single-level wildcard: not supported
	}
	v, ok := normDomain(s)
	if !ok {
		return false, false
	}
	if suffix {
		d.dom.suffix[v] = struct{}{}
	} else {
		d.dom.exact[v] = struct{}{}
	}
	return true, false
}

func (d *setData) addClassicalLine(line string) (ok, unsupported bool) {
	typ, rest, found := strings.Cut(line, ",")
	typ = strings.TrimSpace(typ)
	if !found || !validType(typ) {
		return false, false
	}
	fields := strings.Split(rest, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	val := fields[0]
	noResolve := false
	for _, f := range fields[1:] {
		if !strings.EqualFold(f, "no-resolve") {
			return false, true // policy or option we do not understand
		}
		noResolve = true
	}
	switch strings.ToUpper(typ) {
	case "DOMAIN":
		v, ok := normDomain(val)
		if !ok {
			return false, false
		}
		d.dom.exact[v] = struct{}{}
	case "DOMAIN-SUFFIX":
		v, ok := normDomain(strings.TrimPrefix(val, "."))
		if !ok {
			return false, false
		}
		d.dom.suffix[v] = struct{}{}
	case "DOMAIN-KEYWORD":
		v, ok := normKeyword(val)
		if !ok {
			return false, false
		}
		d.dom.keywords = append(d.dom.keywords, v)
	case "IP-CIDR", "IP-CIDR6":
		p, ok := parseCIDR(val, true)
		if !ok {
			return false, false
		}
		if noResolve {
			d.ipNR.add(p)
		} else {
			d.ip.add(p)
		}
	case "GEOIP":
		v, ok := normGeo(val)
		if strings.EqualFold(val, "lan") {
			v, ok = geoPrivate, true
		}
		if !ok {
			return false, false
		}
		if noResolve {
			d.geoNR = append(d.geoNR, v)
		} else {
			d.geo = append(d.geo, v)
		}
	case "DST-PORT":
		lo, hi, ok := parsePortRange(val)
		if !ok {
			return false, false
		}
		d.ports = append(d.ports, portRange{lo, hi})
	default:
		return false, true
	}
	return true, false
}

func validType(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
