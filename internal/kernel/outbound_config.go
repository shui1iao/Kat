package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
	"github.com/shui1iao/Kat/internal/route"
)

// Limits for the outbound graph (design constants).
const (
	maxOutbounds  = 256
	maxGroups     = 64
	maxChainDepth = 4 // proxy hops only; groups and direct do not count
)

// OutboundConfig is one root "outbounds" entry (outbound.Options, strictly decoded).
type OutboundConfig outbound.Options

// GroupConfig is one root "groups" entry (group.Options, strictly decoded).
type GroupConfig group.Options

// RuleSetConfig is one root "rule_sets" entry (route.RuleSetOptions, strictly decoded).
type RuleSetConfig route.RuleSetOptions

// GeoIPConfig is the root "geoip" block (route.GeoIPOptions, strictly decoded).
type GeoIPConfig route.GeoIPOptions

// strictPlain rejects (recursively) explicit null anywhere and explicit empty
// strings as object member values, then decodes with unknown fields rejected.
// The routing extension blocks have no field whose meaning is "null" or "".
func strictPlain(b []byte, v any) error {
	var raw any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&raw) != nil {
		return errNetworkConfig
	}
	if _, ok := raw.(map[string]any); !ok {
		return errNetworkConfig
	}
	if !strictTree(raw) {
		return errNetworkConfig
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errNetworkConfig
	}
	return nil
}
func strictTree(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case map[string]any:
		for _, m := range x {
			if s, ok := m.(string); ok && s == "" {
				return false
			}
			if !strictTree(m) {
				return false
			}
		}
	case []any:
		for _, m := range x {
			if !strictTree(m) {
				return false
			}
		}
	}
	return true
}
func (o *OutboundConfig) UnmarshalJSON(b []byte) error {
	var p outbound.Options
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = OutboundConfig(p)
	return nil
}
func (o *GroupConfig) UnmarshalJSON(b []byte) error {
	var p group.Options
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = GroupConfig(p)
	return nil
}
func (o *RuleSetConfig) UnmarshalJSON(b []byte) error {
	var p route.RuleSetOptions
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = RuleSetConfig(p)
	return nil
}

// GeositeConfig is the root "geosite" block (v2fly geosite.dat source).
type GeositeConfig route.GeoIPOptions

// ASNConfig is the root "asn" block (MaxMind DB with ASN records).
type ASNConfig route.GeoIPOptions

func (o *GeositeConfig) UnmarshalJSON(b []byte) error {
	var p route.GeoIPOptions
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = GeositeConfig(p)
	return nil
}
func (o *ASNConfig) UnmarshalJSON(b []byte) error {
	var p route.GeoIPOptions
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = ASNConfig(p)
	return nil
}
func (o *GeoIPConfig) UnmarshalJSON(b []byte) error {
	var p route.GeoIPOptions
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = GeoIPConfig(p)
	return nil
}

// validOutboundName: 1..64 bytes of valid UTF-8 without spaces or control
// characters (the same alphabet the route package accepts for references).
func validOutboundName(s string) bool {
	if s == "" || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.IsSpace(c) || c == '=' {
			return false
		}
	}
	return true
}

func validProviderNodeName(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validateOutbound(o outbound.Options) error {
	switch o.Type {
	case "socks5":
		return socks5.Validate(o)
	case "shadowsocks":
		return ss.Validate(o)
	case "trojan":
		return trojan.Validate(o)
	case "anytls":
		return anytls.Validate(o)
	}
	return fmt.Errorf("outbound %q: unsupported type", o.Name)
}

// routeOptions converts the root routing blocks into route.Options.
func (c *Config) routeOptions() route.Options {
	var o route.Options
	if c.Routing != nil {
		o.Final = c.Routing.Final
		for _, r := range c.Routing.Rules {
			x := r.RouteRuleExt
			o.Rules = append(o.Rules, route.Rule{Domain: r.Domain, DomainSuffix: r.DomainSuffix, DomainKeyword: r.DomainKeyword, IPCIDR: r.IPCIDR, SrcIPCIDR: r.SrcIPCIDR, GeoIP: r.GeoIP, DstPort: r.DstPort, Network: r.Network, RuleSet: r.RuleSet, NoResolve: r.NoResolve, Action: r.Action, Outbound: r.Outbound,
				DomainRegex: x.DomainRegex, DomainWildcard: x.DomainWildcard, Geosite: x.Geosite, IPSuffix: x.IPSuffix, IPASN: x.IPASN, SrcIPASN: x.SrcIPASN, SrcGeoIP: x.SrcGeoIP, SrcPort: x.SrcPort, InPort: x.InPort, InName: x.InName, InType: x.InType, Protocol: x.Protocol, And: x.And, Or: x.Or, Not: x.Not})
		}
	}
	for _, s := range c.RuleSets {
		o.RuleSets = append(o.RuleSets, route.RuleSetOptions(s))
	}
	if c.GeoIP != nil {
		g := route.GeoIPOptions(*c.GeoIP)
		o.GeoIP = &g
	}
	if c.Geosite != nil {
		g := route.GeoIPOptions(*c.Geosite)
		o.Geosite = &g
	}
	if c.ASN != nil {
		g := route.GeoIPOptions(*c.ASN)
		o.ASN = &g
	}
	return o
}

// validateOutbounds performs every static check of the outbound/group/rule
// graph. It never performs network I/O (protocol Validate may read a CA file).
// On success c.route holds the normalized route.Options used by Start.
func (c *Config) validateOutbounds() error {
	if len(c.Outbounds)-c.providerNodes > maxOutbounds || len(c.Groups) > maxGroups {
		return errors.New("too many outbounds or groups")
	}
	kind := map[string]byte{} // 'o' outbound, 'g' group
	for i := range c.Outbounds {
		o := outbound.Options(c.Outbounds[i])
		nameOK := validOutboundName(o.Name)
		if i >= len(c.Outbounds)-c.providerNodes {
			nameOK = validProviderNodeName(o.Name)
		}
		if !nameOK || o.Name == "direct" || o.Name == "reject" || kind[o.Name] != 0 {
			return fmt.Errorf("outbound %d: invalid, reserved or duplicate name", i)
		}
		kind[o.Name] = 'o'
		if o.Via != "" && !validOutboundName(o.Via) {
			return fmt.Errorf("outbound %q: invalid via", o.Name)
		}
		if e := validateOutbound(o); e != nil {
			return e
		}
	}
	for i := range c.Groups {
		g := group.Options(c.Groups[i])
		if !validOutboundName(g.Name) || g.Name == "direct" || g.Name == "reject" || kind[g.Name] != 0 {
			return fmt.Errorf("group %d: invalid, reserved or duplicate name", i)
		}
		kind[g.Name] = 'g'
		if e := group.Validate(g); e != nil {
			return e
		}
	}
	exists := func(name string, allowReject bool) bool {
		return name == "direct" || allowReject && name == "reject" || kind[name] != 0
	}
	for _, o := range c.Outbounds {
		if o.Via != "" && !exists(o.Via, false) {
			return fmt.Errorf("outbound %q: via refers to an unknown outbound", o.Name)
		}
	}
	providers := map[string]bool{}
	for _, p := range c.Providers {
		providers[p.Name] = true
		if p.Via != "" && !exists(p.Via, false) {
			return fmt.Errorf("provider %q: unknown via", p.Name)
		}
	}
	relays := map[string][]string{}
	for _, g := range c.Groups {
		for _, u := range g.Use {
			if !providers[u] {
				return fmt.Errorf("group %q: unknown provider %q", g.Name, u)
			}
		}
		if g.Type == group.TypeRelay {
			relays[g.Name] = g.Members
			for _, m := range g.Members[1:] {
				if kind[m] != 'o' {
					return fmt.Errorf("relay %q: subsequent members must be protocol outbounds", g.Name)
				}
				for _, o := range c.Outbounds {
					if o.Name == m && o.Via != "" {
						return fmt.Errorf("relay %q: subsequent members cannot have via", g.Name)
					}
				}
			}
		}
		for _, m := range g.Members {
			if !exists(m, true) && !(len(c.Providers) > 0 && !c.expanded && group.Options(g).Dynamic()) {
				return fmt.Errorf("group %q: unknown member", g.Name)
			}
		}
	}
	// Dependency graph: outbound -> via, group -> members. Detect cycles and
	// measure the proxy-hop chain depth.
	edges := map[string][]string{}
	for _, o := range c.Outbounds {
		if o.Via != "" && o.Via != "direct" {
			edges[o.Name] = []string{o.Via}
		}
	}
	for _, g := range c.Groups {
		for _, m := range g.Members {
			if m != "direct" && m != "reject" {
				edges[g.Name] = append(edges[g.Name], m)
			}
		}
	}
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	depth := map[string]int{}
	var visit func(n string) error
	visit = func(n string) error {
		switch color[n] {
		case grey:
			return errors.New("outbound/group dependency cycle")
		case black:
			return nil
		}
		color[n] = grey
		d := 0
		for _, m := range edges[n] {
			if e := visit(m); e != nil {
				return e
			}
			d = max(d, depth[m])
		}
		if ms, ok := relays[n]; ok {
			d = depth[ms[0]] + len(ms) - 1
		}
		if kind[n] == 'o' {
			d++
		}
		if d > maxChainDepth {
			return errors.New("proxy chain deeper than 4 hops")
		}
		depth[n] = d
		color[n] = black
		return nil
	}
	for _, o := range c.Outbounds {
		if e := visit(o.Name); e != nil {
			return e
		}
	}
	for _, g := range c.Groups {
		if e := visit(g.Name); e != nil {
			return e
		}
	}
	ro := c.routeOptions()
	if e := ro.Validate(); e != nil {
		return e
	}
	for _, name := range ro.ReferencedOutbounds() {
		if kind[name] == 0 {
			return errors.New("routing refers to an unknown outbound or group")
		}
	}
	if e := c.validateInboundRefs(ro); e != nil {
		return e
	}
	c.route = ro
	return nil
}

// topoOrder returns outbound and group names so that every via/member comes
// before its user. Call only after validateOutbounds succeeded.
func (c *Config) topoOrder() []string {
	deps := map[string][]string{}
	var all []string
	for _, o := range c.Outbounds {
		all = append(all, o.Name)
		if o.Via != "" && o.Via != "direct" {
			deps[o.Name] = []string{o.Via}
		}
	}
	for _, g := range c.Groups {
		all = append(all, g.Name)
		for _, m := range g.Members {
			if m != "direct" && m != "reject" {
				deps[g.Name] = append(deps[g.Name], m)
			}
		}
	}
	done := map[string]bool{}
	var out []string
	var visit func(string)
	visit = func(n string) {
		if done[n] {
			return
		}
		done[n] = true
		for _, m := range deps[n] {
			visit(m)
		}
		out = append(out, n)
	}
	for _, n := range all {
		visit(n)
	}
	return out
}
