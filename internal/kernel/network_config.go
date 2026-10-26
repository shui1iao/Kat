package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/shui1iao/Kat/internal/route"
)

var errNetworkConfig = errors.New("invalid DNS or routing configuration")

type DNSOptions struct {
	Server       string `json:"server,omitempty"`
	CacheEntries *int   `json:"cache_entries,omitempty"`
}
type RoutingOptions struct {
	Rules []RouteRule `json:"rules,omitempty"`
	// Final applies when no rule matches: direct (default) | reject | outbound/group name.
	Final string `json:"final,omitempty"`
}

// RouteRule is one routing rule: exactly one match field and exactly one of
// action (direct|reject) or outbound (outbound/group name). The legacy form
// {domain|domain_suffix|ip_cidr, action} keeps its exact meaning.
type RouteRule struct {
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
	prefix        netip.Prefix
	// 0.7.0 conditions (validated by the route package).
	RouteRuleExt
}

// RouteRuleExt holds the rule conditions added in 0.7.0. Logical and/or/not
// take sub-conditions: one match field each, no action or outbound.
type RouteRuleExt struct {
	DomainRegex    string       `json:"domain_regex,omitempty"`
	DomainWildcard string       `json:"domain_wildcard,omitempty"`
	Geosite        string       `json:"geosite,omitempty"`
	IPSuffix       string       `json:"ip_suffix,omitempty"`
	IPASN          string       `json:"ip_asn,omitempty"`
	SrcIPASN       string       `json:"src_ip_asn,omitempty"`
	SrcGeoIP       string       `json:"src_geoip,omitempty"`
	SrcPort        string       `json:"src_port,omitempty"`
	InPort         string       `json:"in_port,omitempty"`
	InName         string       `json:"in_name,omitempty"`
	InType         string       `json:"in_type,omitempty"`
	Protocol       string       `json:"protocol,omitempty"`
	And            []route.Rule `json:"and,omitempty"`
	Or             []route.Rule `json:"or,omitempty"`
	Not            *route.Rule  `json:"not,omitempty"`
}

var routeMatchKeys = []string{"domain", "domain_suffix", "domain_keyword", "ip_cidr", "src_ip_cidr", "geoip", "dst_port", "network", "rule_set",
	"domain_regex", "domain_wildcard", "geosite", "ip_suffix", "ip_asn", "src_ip_asn", "src_geoip", "src_port", "in_port", "in_name", "in_type", "protocol"}

// routeLogicKeys take sub-conditions instead of a string.
var routeLogicKeys = []string{"and", "or", "not"}

// legacy reports whether the rule has the pre-routing-core shape.
func (r RouteRule) legacy() bool {
	return r.Outbound == "" && r.DomainKeyword == "" && r.SrcIPCIDR == "" && r.GeoIP == "" && r.DstPort == "" && r.Network == "" && r.RuleSet == "" && !r.NoResolve && r.RouteRuleExt.empty()
}

func (x *RouteRuleExt) empty() bool {
	return x.DomainRegex == "" && x.DomainWildcard == "" && x.Geosite == "" && x.IPSuffix == "" && x.IPASN == "" && x.SrcIPASN == "" && x.SrcGeoIP == "" && x.SrcPort == "" && x.InPort == "" && x.InName == "" && x.InType == "" && x.Protocol == "" && x.And == nil && x.Or == nil && x.Not == nil
}

// All new optional objects reject explicit null, unknown keys and null members.
func strictNetworkJSON(b []byte, v any) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || m == nil {
		return errNetworkConfig
	}
	for _, v := range m {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errNetworkConfig
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errNetworkConfig
	}
	return nil
}
func (c *Config) UnmarshalJSON(b []byte) error {
	type plain Config
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return errNetworkConfig
	}
	for _, k := range []string{"dns", "routing", "outbounds", "groups", "providers", "rule_sets", "geoip", "geosite", "asn"} {
		if v, ok := raw[k]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errNetworkConfig
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(c))
}
func (o *DNSOptions) UnmarshalJSON(b []byte) error {
	type plain DNSOptions
	var p plain
	if e := strictNetworkJSON(b, &p); e != nil {
		return e
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if _, ok := m["server"]; ok && p.Server == "" {
		return errNetworkConfig
	}
	*o = DNSOptions(p)
	return nil
}
func (o *RoutingOptions) UnmarshalJSON(b []byte) error {
	type plain RoutingOptions
	var p plain
	if e := strictNetworkJSON(b, &p); e != nil {
		return e
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if _, ok := m["final"]; ok && p.Final == "" {
		return errNetworkConfig
	}
	*o = RoutingOptions(p)
	return nil
}
func (o *RouteRule) UnmarshalJSON(b []byte) error {
	type plain RouteRule
	var p plain
	if e := strictNetworkJSON(b, &p); e != nil {
		return e
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	n := 0
	for _, k := range routeMatchKeys {
		if v, ok := m[k]; ok {
			var s string
			if json.Unmarshal(v, &s) != nil || s == "" {
				return errNetworkConfig
			}
			n++
		}
	}
	for _, k := range routeLogicKeys {
		if v, ok := m[k]; ok {
			if !strictCondJSON(v) {
				return errNetworkConfig
			}
			n++
		}
	}
	if n != 1 {
		return errNetworkConfig
	}
	// Exactly one non-empty action|outbound.
	act, okA := m["action"]
	ob, okO := m["outbound"]
	if okA == okO {
		return errNetworkConfig
	}
	for _, v := range []json.RawMessage{act, ob} {
		if v != nil {
			var s string
			if json.Unmarshal(v, &s) != nil || s == "" {
				return errNetworkConfig
			}
		}
	}
	*o = RouteRule(p)
	return nil
}

// strictCondJSON rejects explicit null and empty strings anywhere inside a
// logical rule's sub-conditions (the decoder already rejects unknown keys).
func strictCondJSON(b []byte) bool {
	var v any
	if json.Unmarshal(b, &v) != nil || v == nil {
		return false
	}
	return strictTree(v)
}

func dnsName(s string) (string, error) {
	s = strings.TrimSuffix(s, ".")
	if len(s) < 1 || len(s) > 253 {
		return "", errNetworkConfig
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errNetworkConfig
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", errNetworkConfig
			}
		}
	}
	return strings.ToLower(s), nil
}

type dnsEndpoint struct{ scheme, host, port, url string }

func parseDNS(s string) (dnsEndpoint, error) {
	if s == "" || s == "system" {
		return dnsEndpoint{scheme: "system"}, nil
	}
	scheme := "udp"
	authority := s
	path := ""
	if strings.Contains(s, "://") {
		u, e := url.Parse(s)
		if e != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
			return dnsEndpoint{}, errNetworkConfig
		}
		scheme = u.Scheme
		authority = u.Host
		path = u.EscapedPath()
		if scheme != "udp" && scheme != "tcp" && scheme != "https" {
			return dnsEndpoint{}, errNetworkConfig
		}
		if scheme == "https" {
			if path == "" || path[0] != '/' {
				return dnsEndpoint{}, errNetworkConfig
			}
		} else if path != "" {
			return dnsEndpoint{}, errNetworkConfig
		}
	}
	host := authority
	port := "53"
	if scheme == "https" {
		port = "443"
	}
	if ip, e := netip.ParseAddr(authority); e == nil {
		host = ip.String()
	} else if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		host = authority[1 : len(authority)-1]
	} else if strings.Contains(authority, ":") {
		h, p, e := net.SplitHostPort(authority)
		if e != nil {
			return dnsEndpoint{}, errNetworkConfig
		}
		host, port = h, p
	} else if strings.HasPrefix(authority, "[") {
		return dnsEndpoint{}, errNetworkConfig
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return dnsEndpoint{}, errNetworkConfig
		}
		host = ip.String()
	} else {
		h, e := dnsName(host)
		if e != nil {
			return dnsEndpoint{}, e
		}
		host = h
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return dnsEndpoint{}, errNetworkConfig
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return dnsEndpoint{}, errNetworkConfig
		}
	}
	ep := dnsEndpoint{scheme: scheme, host: host, port: strconv.Itoa(n)}
	if scheme == "https" {
		ep.url = "https://" + net.JoinHostPort(host, ep.port) + path
	}
	return ep, nil
}
func (c *Config) validateNetwork() error {
	if c.DNS != nil {
		ep, e := parseDNS(c.DNS.Server)
		if e != nil {
			return e
		}
		if c.DNS.CacheEntries != nil {
			n := *c.DNS.CacheEntries
			if n < 0 || n > 4096 || ep.scheme == "system" && n != 0 {
				return errNetworkConfig
			}
		}
	}
	if c.Routing == nil {
		return nil
	}
	if len(c.Routing.Rules) > 1024 {
		return errNetworkConfig
	}
	for i := range c.Routing.Rules {
		r := &c.Routing.Rules[i]
		if !r.legacy() {
			// New rule forms are validated and normalized by the route package
			// (validateOutbounds); only the legacy shape is pre-normalized here.
			continue
		}
		if r.Action != "direct" && r.Action != "reject" {
			return errNetworkConfig
		}
		n := 0
		for _, p := range []*string{&r.Domain, &r.DomainSuffix} {
			if *p != "" {
				n++
				v, e := dnsName(*p)
				if e != nil {
					return e
				}
				*p = v
			}
		}
		if r.IPCIDR != "" {
			n++
			p, e := netip.ParsePrefix(r.IPCIDR)
			if e != nil || p.Addr().Zone() != "" {
				return errNetworkConfig
			}
			// Canonical mapped-v4 prefixes become IPv4. Broader legal prefixes
			// remain IPv6 and are masked normally; they do not turn ::/0 into a
			// catch-all for ordinary IPv4 candidates.
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			r.prefix = p.Masked()
		}
		if n != 1 {
			return errNetworkConfig
		}
	}
	return nil
}
