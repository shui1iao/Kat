package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
	"github.com/shui1iao/Kat/internal/route"
)

var errUnknownOutbound = errors.New("routing selected an unknown outbound")

// rejectOutbound is the built-in "reject" member (select groups may use it).
type rejectOutbound struct{}

func (rejectOutbound) Name() string { return "reject" }
func (rejectOutbound) Type() string { return "reject" }
func (rejectOutbound) UDP() bool    { return true }
func (rejectOutbound) Close() error { return nil }
func (rejectOutbound) DialTCP(context.Context, outbound.Addr) (net.Conn, error) {
	return nil, outbound.ErrRejected
}
func (rejectOutbound) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrRejected
}

// routingRuntime owns every outbound, group and the rule engine of a Server.
type routingRuntime struct {
	nodes     map[string]outbound.Outbound // includes built-in direct and reject
	outbounds []outbound.Outbound          // protocol outbounds, dependency order
	groups    []group.Group                // dependency order
	engine    *route.Engine
	proxies   int // configured outbounds + groups: per-association UDP session cap
}

func newProtocolOutbound(o outbound.Options, under outbound.Dialer) (outbound.Outbound, error) {
	switch o.Type {
	case "socks5":
		return socks5.New(o, under)
	case "shadowsocks":
		return ss.New(o, under)
	case "trojan":
		return trojan.New(o, under)
	case "anytls":
		return anytls.New(o, under)
	}
	return nil, fmt.Errorf("outbound %q: unsupported type", o.Name)
}

// A relay borrows its final clone; routingRuntime owns and closes every clone.
type relayOutbound struct {
	outbound.Outbound
	name string
}

func (r relayOutbound) Name() string { return r.name }
func (r relayOutbound) Type() string { return group.TypeRelay }
func (r relayOutbound) Close() error { return nil }

// lookup is the resolver for Decide and for the direct first hop: Kat's dns
// settings (system or the configured upstream).
func (s *Server) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if s.dns == nil {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	return s.dns.lookup(ctx, host)
}

// buildRouting constructs direct, reject, every outbound and group in
// dependency order and the rule engine. It performs no network I/O (the
// engine only reads local rule-set/GeoIP files).
func (s *Server) buildRouting() (*routingRuntime, error) {
	c := &s.cfg
	rt := &routingRuntime{nodes: map[string]outbound.Outbound{}, proxies: len(c.Outbounds) + len(c.Groups)}
	var b4, b6 netip.Addr
	if c.UDPBindIPv4 != "" {
		b4, _ = netip.ParseAddr(c.UDPBindIPv4)
	}
	if c.UDPBindIPv6 != "" {
		b6, _ = netip.ParseAddr(c.UDPBindIPv6)
	}
	do := direct.Options{Resolve: s.lookup, BindIPv4: b4.Unmap(), BindIPv6: b6, Timeout: c.Limits.DialTimeout.value()}
	if s.guardActive() {
		do.Guard = s.directGuard
	}
	if s.directTFO() {
		do.Control = tfoDialControl
	}
	rt.nodes["direct"] = direct.New(do)
	rt.nodes["reject"] = rejectOutbound{}
	outs := map[string]outbound.Options{}
	for _, o := range c.Outbounds {
		outs[o.Name] = outbound.Options(o)
	}
	groups := map[string]group.Options{}
	for _, g := range c.Groups {
		groups[g.Name] = group.Options(g)
	}
	for _, name := range c.topoOrder() {
		if o, ok := outs[name]; ok {
			via := o.Via
			if via == "" {
				via = "direct"
			}
			// The server dial of an outbound is not client traffic: no guard, no hop.
			ob, e := newProtocolOutbound(o, underlay{rt.nodes[via]})
			if e != nil {
				rt.close()
				return nil, e
			}
			rt.nodes[name] = ob
			rt.outbounds = append(rt.outbounds, ob)
			continue
		}
		g := groups[name]
		if g.Type == group.TypeRelay {
			prev := rt.nodes[g.Members[0]]
			for _, m := range g.Members[1:] {
				ob, e := newProtocolOutbound(outs[m], underlay{prev})
				if e != nil {
					rt.close()
					return nil, e
				}
				rt.outbounds = append(rt.outbounds, ob)
				prev = ob
			}
			rt.nodes[name] = relayOutbound{Outbound: prev, name: name}
			continue
		}
		members := make([]outbound.Outbound, len(g.Members))
		for i, m := range g.Members {
			members[i] = member{rt.nodes[m]}
		}
		gr, e := group.New(g, members, s.event)
		if e != nil {
			rt.close()
			return nil, e
		}
		rt.nodes[name] = gr
		rt.groups = append(rt.groups, gr)
	}
	engine, e := route.NewEngine(c.route, rt.dialVia, s.event)
	if e != nil {
		rt.close()
		return nil, e
	}
	rt.engine = engine
	return rt, nil
}

// dialVia maps a rule-set/GeoIP "via" name to a DialContext over that
// outbound or group (default direct).
func (rt *routingRuntime) dialVia(via string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if via == "" {
		via = "direct"
	}
	ob := rt.nodes[via]
	if ob == nil || via == "reject" {
		return nil, errUnknownOutbound
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errors.New("unsupported network")
		}
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 {
			return nil, errors.New("invalid port")
		}
		if ip, e := netip.ParseAddr(host); e == nil {
			host = ip.Unmap().String()
		} else {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
		}
		return ob.DialTCP(ctx, outbound.Addr{Host: host, Port: uint16(n)})
	}, nil
}

func (rt *routingRuntime) start(ctx context.Context) {
	for _, g := range rt.groups {
		g.Start(ctx)
	}
	rt.engine.Start(ctx)
}

// close stops groups (probes), then outbounds (session pools), then the engine
// (background downloads). Each Close waits for its own workers.
func (rt *routingRuntime) close() {
	if rt == nil {
		return
	}
	for i := len(rt.groups) - 1; i >= 0; i-- {
		rt.groups[i].Close()
	}
	for i := len(rt.outbounds) - 1; i >= 0; i-- {
		rt.outbounds[i].Close()
	}
	if rt.engine != nil {
		rt.engine.Close()
	}
}

// ---- client source address (for src_ip_cidr) ----

// withSource attaches the client address to ctx unless one is already set.
// It is used only for routing decisions and never logged.
func withSource(ctx context.Context, a net.Addr) context.Context {
	if outbound.SourceFrom(ctx).IsValid() {
		return ctx
	}
	ip := addrIP(a)
	if !ip.IsValid() {
		return ctx
	}
	return outbound.WithSource(ctx, ip)
}
func addrIP(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		if v == nil {
			return netip.Addr{}
		}
		return v.AddrPort().Addr().WithZone("").Unmap()
	case *net.UDPAddr:
		if v == nil {
			return netip.Addr{}
		}
		return v.AddrPort().Addr().WithZone("").Unmap()
	case nil:
		return netip.Addr{}
	}
	ap, e := netip.ParseAddrPort(a.String())
	if e != nil {
		return netip.Addr{}
	}
	return ap.Addr().WithZone("").Unmap()
}
func sourceOf(ctx context.Context) netip.Addr { return outbound.SourceFrom(ctx) }

// ---- routing decisions ----

// router returns the Start-built engine. Servers assembled by hand in unit
// fixtures (no Start) get a transient rules-only engine for the current cfg.
func (s *Server) router() (*route.Engine, error) {
	if s.rt != nil {
		return s.rt.engine, nil
	}
	o := s.cfg.routeOptions()
	if e := o.Validate(); e != nil {
		return nil, errNetworkConfig
	}
	return route.NewEngine(o, nil, nil)
}

// decide applies the existing destination checks (zero port, DNS name
// syntax) and then the rule engine. Reject is returned as errRouteReject;
// Direct carries the dialable candidates; host is the normalized target host.
func (s *Server) decide(ctx context.Context, network string, a Address, src netip.Addr) (d route.Decision, host string, err error) {
	if a.Port == 0 {
		return d, "", errors.New("zero destination port")
	}
	m := route.Metadata{Network: network, Port: a.Port, Source: src}
	if im := inboundMetaOf(ctx); im != nil {
		m.SrcPort, m.InPort, m.InName, m.InType = im.srcPort, im.port, im.name, im.typ
	}
	if sn := sniffOf(ctx); sn != nil {
		m.Protocol = sn.proto
		a = sn.target(a)
		if sn.host != "" {
			m.SniffHost = sn.host
		}
	}
	if ip, e := netip.ParseAddr(a.Host); e == nil {
		m.IP = ip
		host = ip.Unmap().String()
	} else {
		name, e := dnsName(a.Host)
		if e != nil {
			return d, "", errDNS
		}
		m.Host, host = name, name
	}
	r, e := s.router()
	if e != nil {
		return d, "", e
	}
	d, e = r.Decide(ctx, m, s.lookup)
	if s.rt == nil {
		r.Close()
	}
	if e != nil {
		return d, host, e
	}
	switch d.Kind {
	case route.Reject:
		return d, host, errRouteReject
	case route.Direct:
		if len(d.Candidates) == 0 {
			return d, host, errRouteReject
		}
	case route.Proxy:
		if s.rt == nil || s.rt.nodes[d.Outbound] == nil {
			return d, host, errUnknownOutbound
		}
	}
	return d, host, nil
}

// dialProxy dials through the selected outbound/group. The whole budget
// (dial_timeout + handshake_timeout) is measured from the dial start and
// covers the proxy chain handshakes; the caller still holds its dialSlots slot.
func (s *Server) dialProxy(parent context.Context, start time.Time, name string, host string, port uint16) (net.Conn, error) {
	l := s.cfg.Limits
	ctx, cancel := context.WithDeadline(parent, start.Add(l.DialTimeout.value()+l.HandshakeTimeout.value()))
	defer cancel()
	h := &hops{}
	ctx = context.WithValue(ctx, hopsKey{}, h)
	c, e := s.rt.nodes[name].DialTCP(ctx, outbound.Addr{Host: host, Port: port})
	if f := flowOf(parent); f != nil {
		f.mu.Lock()
		if e == nil {
			f.chain = h.chain(name)
		}
		f.mu.Unlock()
		if e == nil {
			// Only the head was metered by route(); add the chosen members.
			f.meters = append(f.meters, s.chainCounters(f.chain[1:])...)
		}
	}
	if e != nil {
		switch {
		case errors.Is(e, outbound.ErrRejected):
			s.failure(failRoute, "outbound", -1)
		case blockedError(e):
			s.failure(failBlocked, "outbound", -1)
		case parent.Err() != nil:
		default:
			s.failure(failOutboundDial, "outbound", -1)
		}
		return nil, e
	}
	return c, nil
}

// ---- events ----

// Event lines: "kat event=NAME key=value ... suppressed=N". Only names,
// counts and classes are ever passed by the emitters (EventSink contract);
// values are additionally sanitized to one bounded token each.
var knownEvents = map[string]int{"group_switch": 0, "rule_set_loaded": 1, "rule_set_update_failed": 2, "geoip_loaded": 3, "geoip_update_failed": 4,
	// 0.7.0: geosite and ASN databases
	"geosite_loaded": 5, "geosite_update_failed": 6, "geosite_category_missing": 7, "asn_loaded": 8, "asn_update_failed": 9}

const (
	eventWindow = 10 * time.Second
	eventBurst  = 10
)

type eventLog struct {
	mu      sync.Mutex
	write   func([]byte) error
	allow   func(event string) bool // nil = every event; else the log level gate
	closed  bool
	buckets [11]struct { // knownEvents + "other"
		start      time.Time
		count      int
		suppressed uint64
	}
}

func eventToken(s string, max int) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() >= max {
			break
		}
		if c == utf8.RuneError || unicode.IsControl(c) || unicode.IsSpace(c) || c == '=' || c == '"' {
			c = '_'
		}
		b.WriteRune(c)
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func (l *eventLog) emit(now time.Time, event string, fields ...string) {
	if l == nil || l.write == nil {
		return
	}
	idx, ok := knownEvents[event]
	if !ok {
		idx, event = len(knownEvents), "other"
		fields = nil
	}
	if l.allow != nil && !l.allow(event) {
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	b := &l.buckets[idx]
	if now.Sub(b.start) >= eventWindow || now.Before(b.start) {
		b.start, b.count = now, 0
	}
	if b.count >= eventBurst {
		b.suppressed++
		l.mu.Unlock()
		return
	}
	b.count++
	suppressed := b.suppressed
	b.suppressed = 0
	l.mu.Unlock()
	line := make([]byte, 0, 160)
	line = append(line, "kat event="...)
	line = append(line, event...)
	for i := 0; i+1 < len(fields) && i < 16; i += 2 {
		line = append(line, ' ')
		line = append(line, eventToken(fields[i], 24)...)
		line = append(line, '=')
		line = append(line, eventToken(fields[i+1], 64)...)
	}
	line = append(line, " suppressed="...)
	line = strconv.AppendUint(line, suppressed, 10)
	line = append(line, '\n')
	// The write happens under the lock so that shutdown (which closes the
	// shared stderr duplicate) can never race with an in-flight write.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if e := l.write(line); e != nil {
		b.suppressed += suppressed + 1
	}
}

// shutdown stops all further event writes; call before the sink is closed.
func (l *eventLog) shutdown() {
	if l != nil {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
	}
}

// eventLevelOf: update failures are warnings, every other event is info.
func eventLevelOf(event string) logLevel {
	if strings.HasSuffix(event, "_failed") {
		return levelWarn
	}
	return levelInfo
}

// eventLevel extracts the event name of a "kat event=NAME ..." line.
func eventLevel(line []byte) logLevel {
	s, _ := strings.CutPrefix(string(line), "kat event=")
	if i := strings.IndexAny(s, " \n"); i >= 0 {
		s = s[:i]
	}
	return eventLevelOf(s)
}

// event is the outbound.EventSink handed to groups and the rule engine.
func (s *Server) event(event string, fields ...string) {
	if strings.HasSuffix(event, "_update_failed") {
		s.failure(failRuleData, "outbound", -1)
	}
	s.events.emit(time.Now(), event, fields...)
}
