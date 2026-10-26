package kernel

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/shui1iao/Kat/internal/route"
)

var errRouteReject = errors.New("destination rejected by routing")

func (r RouteRule) matchDomain(name string) bool {
	return name != "" && (r.Domain == name || r.DomainSuffix != "" && (name == r.DomainSuffix || strings.HasSuffix(name, "."+r.DomainSuffix)))
}

// networkPolicy is false for the default configuration (system DNS, no rules,
// final direct): TCP and UDP then keep the original resolve-and-dial fast path.
func (s *Server) networkPolicy() bool {
	return s.dns != nil && s.dns.ep.scheme != "system" || s.cfg.Routing != nil && (len(s.cfg.Routing.Rules) > 0 || s.cfg.Routing.Final != "" && s.cfg.Routing.Final != "direct")
}

// routeDirect is the legacy (pre-engine) per-candidate evaluation of legacy
// rules. Forwarding uses the route engine (decide); this is kept as the
// reference the existing selector-normalization tests compare against.
func (s *Server) routeDirect(name string, ip netip.Addr) bool {
	if s.cfg.Routing == nil {
		return true
	}
	ip = ip.Unmap()
	for _, r := range s.cfg.Routing.Rules {
		if r.matchDomain(name) || r.IPCIDR != "" && r.prefix.Contains(ip) {
			return r.Action == "direct"
		}
	}
	return true
}

// routeUDP decides one datagram. Without a network policy it is exactly the
// original resolve (system DNS, first address). Otherwise it holds one shared
// dialSlots reservation for the decision (including DNS) and returns either
// the direct candidates or the outbound name plus normalized host.
func (s *Server) routeUDP(ctx context.Context, a Address, src netip.Addr) (candidates []netip.AddrPort, proxy, host string, rule int, err error) {
	if !s.networkPolicy() {
		ip, e := s.resolve(ctx, sniffOf(ctx).target(a))
		if e != nil {
			return nil, "", "", 0, e
		}
		return []netip.AddrPort{ip}, "", "", 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		return nil, "", "", -1, e
	}
	s.counters.Dials.Add(1)
	defer func() { s.dialSlots.release(); s.counters.Dials.Add(-1) }()
	d, host, e := s.decide(ctx, "udp", a, src)
	if e != nil {
		if errors.Is(e, errRouteReject) {
			return nil, "", "", d.Rule, e
		}
		return nil, "", "", -1, e
	}
	if d.Kind == route.Proxy {
		return nil, d.Outbound, host, d.Rule, nil
	}
	out := make([]netip.AddrPort, 0, len(d.Candidates))
	for _, ip := range d.Candidates {
		out = append(out, netip.AddrPortFrom(ip, a.Port))
	}
	return out, "", host, d.Rule, nil
}
