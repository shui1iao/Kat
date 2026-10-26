package route

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

func portIn(ps []portRange, p uint16) bool {
	for _, r := range ps {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

type portRange struct{ lo, hi uint16 }

// setData is an immutable parsed rule set (swapped atomically on update).
// Simple entries live in indexes; everything else (logical rules, ASN,
// geosite, source and inbound conditions, ...) is a list of conditions.
type setData struct {
	dom   domainSet
	ports []portRange
	ip    ipSet    // IP entries that may trigger resolution
	ipNR  ipSet    // IP entries marked no-resolve (only match when an IP is known)
	geo   []string // GEOIP entries that may trigger resolution
	geoNR []string
	extra []*cond
	// extraIP: some extra condition has a destination IP part; mono: no
	// extra condition negates an IP part (see monotone).
	extraIP bool
	mono    bool
	// entries/skipped are reported in rule_set_loaded.
	entries, skipped int
}

func (d *setData) hasIP() bool {
	return !d.ip.empty() || !d.ipNR.empty() || len(d.geo)+len(d.geoNR) > 0 || d.extraIP
}

func (d *setData) needsIP(e *Engine) bool {
	if !d.ip.empty() {
		return true
	}
	for _, c := range d.geo {
		if e.geoUsable(c) {
			return true
		}
	}
	for _, c := range d.extra {
		if e.needsIP(c) {
			return true
		}
	}
	return false
}

func (d *setData) match(e *Engine, q *query, x *ipInfo) bool {
	if d.dom.match(q.host) || portIn(d.ports, q.port) {
		return true
	}
	if x != nil {
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
	for _, c := range d.extra {
		if e.match(c, q, x) {
			return true
		}
	}
	return false
}

// tri is the three-valued evaluation of the set (an OR of its entries)
// before DNS; noResolve is the referencing condition's option.
func (d *setData) tri(e *Engine, q *query, noResolve bool) int8 {
	if d.dom.match(q.host) || portIn(d.ports, q.port) {
		return triTrue
	}
	r := triFalse
	for _, c := range d.extra {
		switch e.tri(c, q) {
		case triTrue:
			return triTrue
		case triUnknown:
			r = triUnknown
		}
	}
	if !noResolve && d.needsIP(e) {
		r = triUnknown
	}
	if noResolve && r == triUnknown {
		// The set's IP parts never trigger a resolution; extra conditions
		// that need the IP are evaluated without it.
		if d.match(e, q, nil) {
			return triTrue
		}
		return triFalse
	}
	return r
}

// matchStatic is the domain/port part only (tests and tools).
func (d *setData) matchStatic(host string, port uint16) bool {
	return d.dom.match(host) || portIn(d.ports, port)
}

// ---- errors ----

// unsupportedError marks content Kat understands syntactically but cannot
// honour (a rule type, field or option Kat does not implement). The whole
// rule set is refused so that nothing is silently ignored.
type unsupportedError struct{ msg string }

func (u *unsupportedError) Error() string { return "route: unsupported " + u.msg }

func unsupported(format string, a ...any) error {
	return &unsupportedError{fmt.Sprintf(format, a...)}
}

// errMalformed marks one malformed entry (skipped and counted).
var errMalformed = errors.New("route: malformed entry")

// parseEnv tells the parsers which databases the configuration provides.
type parseEnv struct{ geoip, asn, geosite bool }

func (p parseEnv) String() string {
	return fmt.Sprintf("%t%t%t", p.geoip, p.asn, p.geosite)
}

// fullEnv accepts every condition (tools and tests).
var fullEnv = parseEnv{true, true, true}

// ---- builder ----

type setBuilder struct {
	d     *setData
	limit int
	bad   int
}

func newBuilder(limit int) *setBuilder {
	return &setBuilder{d: &setData{mono: true}, limit: limit}
}

func (b *setBuilder) count() error {
	b.d.entries++
	if b.d.entries > b.limit {
		return errLimit
	}
	return nil
}

func (b *setBuilder) skip() { b.d.skipped++; b.bad++ }

// addCond indexes a simple condition or appends it to extra.
func (b *setBuilder) addCond(c *cond) error {
	d := b.d
	switch c.kind {
	case kDomain:
		put(&d.dom.exact, c.s)
	case kSuffix:
		put(&d.dom.suffix, c.s)
	case kKeyword:
		d.dom.keywords = append(d.dom.keywords, c.s)
	case kRegex:
		d.dom.regex = append(d.dom.regex, c.re)
	case kWildcard:
		d.dom.globs = append(d.dom.globs, c.s)
	case kIPCIDR:
		if c.noResolve {
			d.ipNR.add(c.prefix)
		} else {
			d.ip.add(c.prefix)
		}
	case kGeoIP:
		if c.noResolve {
			d.geoNR = append(d.geoNR, c.s)
		} else {
			d.geo = append(d.geo, c.s)
		}
	case kDstPort:
		d.ports = append(d.ports, c.ports...)
	default:
		d.extra = append(d.extra, c)
		if hasDstIP(c) {
			d.extraIP = true
		}
		if !monotone(c) {
			d.mono = false
		}
	}
	return b.count()
}

func (b *setBuilder) finish() (*setData, error) {
	if b.d.entries == 0 && b.bad > 0 {
		return nil, errParse
	}
	b.d.ip.build()
	b.d.ipNR.build()
	return b.d, nil
}

// ---- dispatch ----

// parseRuleSet parses a text rule set of the 0.6 formats (tests).
func parseRuleSet(format string, b []byte, limit int) (*setData, error) {
	return parseRuleSetAs(format, "", b, limit, parseEnv{geoip: true})
}

// parseRuleSetAs parses one rule set of any supported format. Malformed
// entries are skipped and counted; the content fails when it is not of the
// format, has more than limit entries, holds only malformed entries, or
// uses anything Kat does not support (unsupportedError).
func parseRuleSetAs(format, behavior string, b []byte, limit int, env parseEnv) (*setData, error) {
	switch format {
	case FormatMRS:
		return parseMRS(behavior, b, limit)
	case FormatSRS:
		return parseSRS(b, limit, env)
	case FormatSingBoxJSON:
		return parseSingBoxJSON(b, limit, env)
	case FormatYAML:
		lines, err := yamlPayload(b)
		if err != nil {
			return nil, err
		}
		return parseLines(behavior, dialMihom, lines, limit, env)
	}
	text, err := textOf(b)
	if err != nil {
		return nil, err
	}
	var lines []string
	for len(text) > 0 {
		var line string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			line, text = text, ""
		}
		lines = append(lines, line)
	}
	switch format {
	case FormatDomain:
		return parseLines("domain", dialKat, lines, limit, env)
	case FormatIPCIDR:
		return parseLines("ipcidr", dialKat, lines, limit, env)
	case FormatClassical:
		return parseLines("classical", dialMihom, lines, limit, env)
	case FormatSurgeDomainSet:
		return parseLines("domain", dialSurge, lines, limit, env)
	case FormatSurgeRuleSet:
		return parseLines("classical", dialSurge, lines, limit, env)
	}
	return nil, errParse
}

func textOf(b []byte) (string, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return "", errParse
	}
	return string(b), nil
}

// parseLines handles every line-oriented behavior (text and YAML payload).
func parseLines(behavior string, dialect int, lines []string, limit int, env parseEnv) (*setData, error) {
	bld := newBuilder(limit)
	for n, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue
		}
		var err error
		switch behavior {
		case "domain":
			if bld.d.dom.addDomainEntry(line, dialect) {
				err = bld.count()
			} else {
				bld.skip()
			}
		case "ipcidr":
			if p, ok := parseCIDR(line, true); ok {
				bld.d.ip.add(p)
				err = bld.count()
			} else {
				bld.skip()
			}
		case "classical":
			var c *cond
			c, err = parseClassical(line, dialect, env, 0)
			switch {
			case err == nil:
				err = bld.addCond(c)
			case errors.Is(err, errMalformed):
				bld.skip()
				err = nil
			}
		default:
			return nil, errParse
		}
		if err != nil {
			var u *unsupportedError
			if errors.As(err, &u) {
				return nil, &unsupportedError{fmt.Sprintf("line %d: %s", n+1, u.msg)}
			}
			return nil, err
		}
	}
	return bld.finish()
}

// ---- classical rules ----

// classicalTypes maps classical (mihomo / Surge) rule types to the Rule field
// they set. Types not listed are unsupported.
var classicalTypes = map[string]func(r *Rule, v string){
	"DOMAIN":          func(r *Rule, v string) { r.Domain = v },
	"DOMAIN-SUFFIX":   func(r *Rule, v string) { r.DomainSuffix = strings.TrimPrefix(v, ".") },
	"DOMAIN-KEYWORD":  func(r *Rule, v string) { r.DomainKeyword = v },
	"DOMAIN-REGEX":    func(r *Rule, v string) { r.DomainRegex = v },
	"DOMAIN-WILDCARD": func(r *Rule, v string) { r.DomainWildcard = v },
	"GEOSITE":         func(r *Rule, v string) { r.Geosite = v },
	"IP-CIDR":         func(r *Rule, v string) { r.IPCIDR = v },
	"IP-CIDR6":        func(r *Rule, v string) { r.IPCIDR = v },
	"IP-SUFFIX":       func(r *Rule, v string) { r.IPSuffix = v },
	"IP-ASN":          func(r *Rule, v string) { r.IPASN = v },
	"GEOIP":           func(r *Rule, v string) { r.GeoIP = v },
	"SRC-GEOIP":       func(r *Rule, v string) { r.SrcGeoIP = v },
	"SRC-IP-ASN":      func(r *Rule, v string) { r.SrcIPASN = v },
	"SRC-IP-CIDR":     func(r *Rule, v string) { r.SrcIPCIDR = v },
	"SRC-IP":          func(r *Rule, v string) { r.SrcIPCIDR = v }, // Surge
	"DST-PORT":        func(r *Rule, v string) { r.DstPort = v },
	"DEST-PORT":       func(r *Rule, v string) { r.DstPort = v }, // Surge
	"SRC-PORT":        func(r *Rule, v string) { r.SrcPort = v },
	"IN-PORT":         func(r *Rule, v string) { r.InPort = v },
	"IN-NAME":         func(r *Rule, v string) { r.InName = v },
	"IN-TYPE":         func(r *Rule, v string) { r.InType = v },
	"NETWORK":         func(r *Rule, v string) { r.Network = v },
	"PROTOCOL":        func(r *Rule, v string) { r.Protocol = v },
}

const maxClassicalDepth = 8

// parseClassical parses "TYPE,VALUE[,no-resolve]" or a logical
// "AND|OR|NOT,((...),(...))" line into a condition.
func parseClassical(line string, dialect int, env parseEnv, depth int) (*cond, error) {
	if depth > maxClassicalDepth {
		return nil, unsupported("logical rule nested deeper than %d", maxClassicalDepth)
	}
	typ, rest, found := strings.Cut(line, ",")
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if !found && (typ == "MATCH" || typ == "FINAL") {
		return nil, unsupported("rule type %s in a rule set", typ)
	}
	if !found || !validType(typ) {
		return nil, errMalformed
	}
	rest = strings.TrimSpace(rest)
	switch typ {
	case "AND", "OR", "NOT":
		return parseLogical(typ, rest, dialect, env, depth)
	}
	set, known := classicalTypes[typ]
	if !known {
		return nil, unsupported("rule type %s", typ)
	}
	var r Rule
	val := rest
	if typ != "DOMAIN-REGEX" {
		fields := strings.Split(rest, ",")
		val = strings.TrimSpace(fields[0])
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if !strings.EqualFold(f, "no-resolve") {
				return nil, unsupported("option %q for %s", f, typ)
			}
			r.NoResolve = true
		}
	}
	if val == "" {
		return nil, errMalformed
	}
	switch typ {
	case "GEOIP", "SRC-GEOIP":
		if strings.EqualFold(val, "lan") {
			val = geoPrivate
		}
	case "PROTOCOL":
		switch strings.ToLower(val) {
		case "tcp", "udp":
			typ, set = "NETWORK", classicalTypes["NETWORK"]
		case "tls", "http", "quic":
		default:
			return nil, unsupported("protocol %s", val)
		}
	case "GEOSITE":
		if !env.geosite {
			return nil, unsupported("GEOSITE without a geosite block")
		}
	case "IP-ASN", "SRC-IP-ASN":
		if !env.asn {
			return nil, unsupported("%s without an asn block", typ)
		}
	}
	set(&r, val)
	if typ != "IP-CIDR" && typ != "IP-CIDR6" && typ != "IP-SUFFIX" && typ != "IP-ASN" && typ != "GEOIP" {
		r.NoResolve = false // harmless option on other types (mihomo accepts it)
	}
	// Database presence is checked above; geoip countries without a block stay
	// accepted (they never match), as in 0.6.
	o := Options{GeoIP: &GeoIPOptions{}, ASN: &GeoIPOptions{}, Geosite: &GeoIPOptions{}}
	if typ == "IP-CIDR" || typ == "IP-CIDR6" {
		p, ok := parseCIDR(val, true)
		if !ok {
			return nil, errMalformed
		}
		return &cond{kind: kIPCIDR, prefix: p, noResolve: r.NoResolve}, nil
	}
	if o.validateLeaf(&r, nil) != nil {
		return nil, errMalformed
	}
	return compileRule(&r, nil), nil
}

func parseLogical(typ, rest string, dialect int, env parseEnv, depth int) (*cond, error) {
	if len(rest) < 2 || rest[0] != '(' || rest[len(rest)-1] != ')' {
		return nil, errMalformed
	}
	inner := rest[1 : len(rest)-1]
	var items []string
	lvl, start := 0, -1
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(':
			if lvl == 0 {
				start = i + 1
			}
			lvl++
		case ')':
			lvl--
			if lvl < 0 {
				return nil, errMalformed
			}
			if lvl == 0 {
				items = append(items, inner[start:i])
			}
		case ',', ' ', '\t':
		default:
			if lvl == 0 {
				return nil, errMalformed
			}
		}
	}
	if lvl != 0 || len(items) == 0 {
		return nil, errMalformed
	}
	c := &cond{}
	switch typ {
	case "AND":
		c.kind = kAnd
	case "OR":
		c.kind = kOr
	case "NOT":
		c.kind = kNot
		if len(items) != 1 {
			return nil, errMalformed
		}
	}
	for _, it := range items {
		s, err := parseClassical(strings.TrimSpace(it), dialect, env, depth+1)
		if err != nil {
			return nil, err
		}
		c.subs = append(c.subs, s)
	}
	if c.kind != kNot && len(c.subs) == 1 {
		return c.subs[0], nil
	}
	return c, nil
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

var _ = netip.Addr{}
