package route

import (
	"net/netip"
	"regexp"

	"strings"
)

// condKind is the type of one routing condition.
type condKind uint8

const (
	kDomain condKind = iota
	kSuffix
	kKeyword
	kRegex
	kWildcard
	kGeosite
	// destination IP conditions
	kIPCIDR
	kIPSuffix
	kIPASN
	kGeoIP
	// source conditions
	kSrcIPCIDR
	kSrcIPASN
	kSrcGeoIP
	kDstPort
	kSrcPort
	kInPort
	kNetwork
	kInName
	kInType
	kProtocol
	kRuleSet
	kAnd
	kOr
	kNot
	kInline   // a group of a sing-box rule: destination domains/CIDRs
	kSrcIPSet // a group of a sing-box rule: source CIDRs
)

// cond is one compiled condition (a leaf or a logical node). It is immutable
// after compilation; rule-set and database contents are read through the
// engine at evaluation time.
type cond struct {
	kind      condKind
	noResolve bool
	s         string
	re        *regexp.Regexp
	prefix    netip.Prefix
	ports     []portRange
	num       uint32
	set       *ruleSet
	subs      []*cond
	inline    *setData
	ipset     *ipSet
}

func isDstIP(k condKind) bool { return k >= kIPCIDR && k <= kGeoIP }

// compileRule turns a validated Rule (match part only) into a cond.
func compileRule(r *Rule, sets map[string]*ruleSet) *cond {
	c := &cond{noResolve: r.NoResolve}
	subs := func(l []Rule) []*cond {
		out := make([]*cond, len(l))
		for i := range l {
			out[i] = compileRule(&l[i], sets)
		}
		return out
	}
	switch {
	case r.And != nil:
		c.kind, c.subs = kAnd, subs(r.And)
	case r.Or != nil:
		c.kind, c.subs = kOr, subs(r.Or)
	case r.Not != nil:
		c.kind, c.subs = kNot, []*cond{compileRule(r.Not, sets)}
	case r.Domain != "":
		c.kind, c.s = kDomain, r.Domain
	case r.DomainSuffix != "":
		c.kind, c.s = kSuffix, r.DomainSuffix
	case r.DomainKeyword != "":
		c.kind, c.s = kKeyword, r.DomainKeyword
	case r.DomainRegex != "":
		c.kind, c.s = kRegex, r.DomainRegex
		c.re, _ = compileDomainRegex(r.DomainRegex)
	case r.DomainWildcard != "":
		c.kind, c.s = kWildcard, r.DomainWildcard
	case r.Geosite != "":
		c.kind, c.s = kGeosite, r.Geosite
	case r.IPCIDR != "":
		c.kind = kIPCIDR
		c.prefix, _ = parseCIDR(r.IPCIDR, false)
	case r.IPSuffix != "":
		c.kind = kIPSuffix
		c.prefix, _ = parseIPSuffix(r.IPSuffix)
	case r.IPASN != "":
		c.kind = kIPASN
		c.num, _ = parseASN(r.IPASN)
	case r.GeoIP != "":
		c.kind, c.s = kGeoIP, r.GeoIP
	case r.SrcIPCIDR != "":
		c.kind = kSrcIPCIDR
		c.prefix, _ = parseCIDR(r.SrcIPCIDR, false)
	case r.SrcIPASN != "":
		c.kind = kSrcIPASN
		c.num, _ = parseASN(r.SrcIPASN)
	case r.SrcGeoIP != "":
		c.kind, c.s = kSrcGeoIP, r.SrcGeoIP
	case r.DstPort != "":
		c.kind = kDstPort
		c.ports, _ = parsePorts(r.DstPort)
	case r.SrcPort != "":
		c.kind = kSrcPort
		c.ports, _ = parsePorts(r.SrcPort)
	case r.InPort != "":
		c.kind = kInPort
		c.ports, _ = parsePorts(r.InPort)
	case r.Network != "":
		c.kind, c.s = kNetwork, r.Network
	case r.InName != "":
		c.kind, c.s = kInName, r.InName
	case r.InType != "":
		c.kind, c.s = kInType, r.InType
	case r.Protocol != "":
		c.kind, c.s = kProtocol, r.Protocol
	case r.RuleSet != "":
		c.kind, c.set = kRuleSet, sets[r.RuleSet]
	}
	return c
}

// ---- evaluation ----

// ipInfo memoizes database lookups of one address during one evaluation.
type ipInfo struct {
	ip      netip.Addr
	geo     string
	geoDone bool
	asn     uint32
	asnDone bool
}

func (e *Engine) asnOf(x *ipInfo) uint32 {
	if !x.asnDone {
		x.asnDone = true
		if e.asn != nil {
			if db := e.asn.db.Load(); db != nil {
				x.asn = db.lookup(x.ip)
			}
		}
	}
	return x.asn
}

func (e *Engine) asnUsable() bool { return e.asn != nil && e.asn.db.Load() != nil }

func suffixMatch(host, s string) bool {
	return host == s || len(host) > len(s) && strings.HasSuffix(host, s) && host[len(host)-len(s)-1] == '.'
}

// match evaluates c. x == nil means the destination IP is not known: IP
// conditions are false (and NOT of them true, as in mihomo).
func (e *Engine) match(c *cond, q *query, x *ipInfo) bool {
	switch c.kind {
	case kDomain:
		return q.host != "" && q.host == c.s
	case kSuffix:
		return q.host != "" && suffixMatch(q.host, c.s)
	case kKeyword:
		return q.host != "" && strings.Contains(q.host, c.s)
	case kRegex:
		return q.host != "" && c.re.MatchString(q.host)
	case kWildcard:
		return q.host != "" && wildcardMatch(c.s, q.host)
	case kGeosite:
		return q.host != "" && e.siteMatch(c.s, q.host)
	case kIPCIDR:
		return x != nil && c.prefix.Contains(x.ip)
	case kIPSuffix:
		return x != nil && ipSuffixMatch(c.prefix, x.ip)
	case kIPASN:
		return x != nil && e.asnOf(x) == c.num
	case kGeoIP:
		return x != nil && e.geoMatch(c.s, x)
	case kSrcIPCIDR:
		return q.src.IsValid() && c.prefix.Contains(q.src)
	case kSrcIPASN:
		return q.src.IsValid() && e.asnOf(q.srcInfo()) == c.num
	case kSrcGeoIP:
		return q.src.IsValid() && e.geoMatch(c.s, q.srcInfo())
	case kDstPort:
		return portIn(c.ports, q.port)
	case kSrcPort:
		return q.srcPort != 0 && portIn(c.ports, q.srcPort)
	case kInPort:
		return q.inPort != 0 && portIn(c.ports, q.inPort)
	case kNetwork:
		return q.network == c.s
	case kInName:
		return q.inName != "" && q.inName == c.s
	case kInType:
		return q.inType != "" && q.inType == c.s
	case kProtocol:
		return q.protocol != "" && q.protocol == c.s
	case kRuleSet:
		return c.set.data.Load().match(e, q, x)
	case kAnd:
		for _, s := range c.subs {
			if !e.match(s, q, x) {
				return false
			}
		}
		return true
	case kOr:
		for _, s := range c.subs {
			if e.match(s, q, x) {
				return true
			}
		}
		return false
	case kNot:
		return !e.match(c.subs[0], q, x)
	case kInline:
		return c.inline.match(e, q, x)
	case kSrcIPSet:
		return q.src.IsValid() && c.ipset.contains(q.src)
	}
	return false
}

// needsIP reports whether a domain target must be resolved before c can be
// decided: it contains a destination IP condition without no_resolve that
// can match now.
func (e *Engine) needsIP(c *cond) bool {
	switch c.kind {
	case kIPCIDR, kIPSuffix:
		return !c.noResolve
	case kIPASN:
		return !c.noResolve && e.asnUsable()
	case kGeoIP:
		return !c.noResolve && e.geoUsable(c.s)
	case kRuleSet:
		return !c.noResolve && c.set.data.Load().needsIP(e)
	case kInline:
		return c.inline.needsIP(e)
	case kAnd, kOr, kNot:
		for _, s := range c.subs {
			if e.needsIP(s) {
				return true
			}
		}
	}
	return false
}

// Three-valued evaluation before DNS: a condition is true or false whatever
// the destination IP turns out to be, or unknown (it needs the IP). Logical
// conditions short-circuit: AND is false as soon as one part is false, OR is
// true as soon as one part is true, so a domain target is resolved only when
// the outcome really depends on its IP.
const (
	triFalse   int8 = 0
	triTrue    int8 = 1
	triUnknown int8 = -1
)

func (e *Engine) tri(c *cond, q *query) int8 {
	switch c.kind {
	case kAnd:
		r := triTrue
		for _, s := range c.subs {
			switch e.tri(s, q) {
			case triFalse:
				return triFalse
			case triUnknown:
				r = triUnknown
			}
		}
		return r
	case kOr:
		r := triFalse
		for _, s := range c.subs {
			switch e.tri(s, q) {
			case triTrue:
				return triTrue
			case triUnknown:
				r = triUnknown
			}
		}
		return r
	case kNot:
		switch e.tri(c.subs[0], q) {
		case triTrue:
			return triFalse
		case triFalse:
			return triTrue
		}
		return triUnknown
	case kRuleSet:
		return c.set.data.Load().tri(e, q, c.noResolve)
	case kInline:
		return c.inline.tri(e, q, false)
	}
	if e.needsIP(c) {
		return triUnknown
	}
	if e.match(c, q, nil) {
		return triTrue
	}
	return triFalse
}

// hasDstIP reports whether c contains any destination IP condition.
func hasDstIP(c *cond) bool {
	switch {
	case isDstIP(c.kind):
		return true
	case c.kind == kRuleSet:
		return c.set.data.Load().hasIP()
	case c.kind == kInline:
		return c.inline.hasIP()
	}
	for _, s := range c.subs {
		if hasDstIP(s) {
			return true
		}
	}
	return false
}

// monotone reports whether learning the destination IP can only turn c from
// false to true (no NOT over an IP condition). Only then may a rule that
// needs an IP be decided early by its domain part.
func monotone(c *cond) bool {
	switch c.kind {
	case kAnd, kOr:
		for _, s := range c.subs {
			if !monotone(s) {
				return false
			}
		}
	case kNot:
		return !hasDstIP(c.subs[0])
	case kRuleSet:
		return c.set.data.Load().mono
	case kInline:
		return c.inline.mono
	}
	return true
}

// ---- statistics keys ----

func condString(r *Rule) string {
	list := func(op string, l []Rule) string {
		parts := make([]string, len(l))
		for i := range l {
			parts[i] = condString(&l[i])
		}
		return op + "(" + strings.Join(parts, ",") + ")"
	}
	nr := ""
	if r.NoResolve {
		nr = ",no_resolve"
	}
	switch {
	case r.And != nil:
		return list("and", r.And)
	case r.Or != nil:
		return list("or", r.Or)
	case r.Not != nil:
		return "not(" + condString(r.Not) + ")"
	case r.Domain != "":
		return "domain:" + r.Domain
	case r.DomainSuffix != "":
		return "domain_suffix:" + r.DomainSuffix
	case r.DomainKeyword != "":
		return "domain_keyword:" + r.DomainKeyword
	case r.DomainRegex != "":
		return "domain_regex:" + r.DomainRegex
	case r.DomainWildcard != "":
		return "domain_wildcard:" + r.DomainWildcard
	case r.Geosite != "":
		return "geosite:" + r.Geosite
	case r.IPCIDR != "":
		return "ip_cidr:" + r.IPCIDR + nr
	case r.IPSuffix != "":
		return "ip_suffix:" + r.IPSuffix + nr
	case r.IPASN != "":
		return "ip_asn:" + r.IPASN + nr
	case r.SrcIPCIDR != "":
		return "src_ip_cidr:" + r.SrcIPCIDR
	case r.SrcIPASN != "":
		return "src_ip_asn:" + r.SrcIPASN
	case r.GeoIP != "":
		return "geoip:" + r.GeoIP + nr
	case r.SrcGeoIP != "":
		return "src_geoip:" + r.SrcGeoIP
	case r.DstPort != "":
		return "dst_port:" + r.DstPort
	case r.SrcPort != "":
		return "src_port:" + r.SrcPort
	case r.InPort != "":
		return "in_port:" + r.InPort
	case r.InName != "":
		return "in_name:" + r.InName
	case r.InType != "":
		return "in_type:" + r.InType
	case r.Network != "":
		return "network:" + r.Network
	case r.Protocol != "":
		return "protocol:" + r.Protocol
	case r.RuleSet != "":
		return "rule_set:" + r.RuleSet + nr
	}
	return "unknown"
}
