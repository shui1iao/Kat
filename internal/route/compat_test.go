package route

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The cases below restate, as Decide table tests, the rule-decision parts of
// internal/kernel/dns_routing_test.go and dns_routing_extra_test.go
// (domain/domain_suffix/ip_cidr with direct/reject only).

const target = "custom-target.example"

func TestCompatKernelRoutingTable(t *testing.T) {
	both := addrs("127.0.0.2", "127.0.0.1") // the kernel fixture's DNS answer order
	cases := []struct {
		name    string
		rules   []Rule
		host    string // domain target
		ip      string // literal target
		dns     []netip.Addr
		dnsErr  error
		kind    Kind
		cands   []netip.Addr
		queries bool
		err     bool
	}{
		// TestDNSRoutingOrderedRulesAndLiteralTCPUDP / TestDNSRoutingDeniedCandidateNetworkCounters:
		// only the allowed candidate is dialed (TCP and UDP use the same decision).
		{name: "per-candidate cidr reject keeps allowed", rules: []Rule{{IPCIDR: "127.0.0.2/32", Action: "reject"}}, host: target, dns: both, kind: Direct, cands: addrs("127.0.0.1"), queries: true},
		// Ordered list: direct-before-reject and reject-before-direct (the four kernel cases).
		{name: "domain direct before cidr reject", rules: []Rule{{Domain: target, Action: "direct"}, {IPCIDR: "127.0.0.0/8", Action: "reject"}}, host: target, dns: both, kind: Direct, cands: both, queries: true},
		{name: "cidr reject before domain direct", rules: []Rule{{IPCIDR: "127.0.0.0/8", Action: "reject"}, {Domain: target, Action: "direct"}}, host: target, dns: both, kind: Reject, queries: true},
		{name: "domain reject before cidr direct: no DNS", rules: []Rule{{Domain: target, Action: "reject"}, {IPCIDR: "127.0.0.0/8", Action: "direct"}}, host: target, dns: both, kind: Reject, queries: false},
		{name: "cidr direct before domain reject", rules: []Rule{{IPCIDR: "127.0.0.1/32", Action: "direct"}, {Domain: target, Action: "reject"}}, host: target, dns: both, kind: Direct, cands: addrs("127.0.0.1"), queries: true},
		// Suffix boundary, exact domain, mapped prefix, default direct (selector normalization block).
		{name: "suffix matches subdomain", rules: []Rule{{DomainSuffix: "Example.COM.", Action: "reject"}}, host: "x.example.com", dns: both, kind: Reject},
		{name: "suffix matches itself", rules: []Rule{{DomainSuffix: "Example.COM.", Action: "reject"}}, host: "example.com", dns: both, kind: Reject},
		{name: "suffix label boundary", rules: []Rule{{DomainSuffix: "Example.COM.", Action: "reject"}}, host: "badexample.com", dns: addrs("127.0.0.1"), kind: Direct, cands: addrs("127.0.0.1"), queries: true},
		{name: "exact domain does not match subdomain", rules: []Rule{{Domain: "example.com", Action: "reject"}}, host: "a.example.com", dns: addrs("127.0.0.1"), kind: Direct, cands: addrs("127.0.0.1"), queries: true},
		{name: "mapped /120 prefix rejects IPv4 literal", rules: []Rule{{DomainSuffix: "example.com", Action: "reject"}, {IPCIDR: "::ffff:192.0.2.0/120", Action: "reject"}}, ip: "192.0.2.1", kind: Reject},
		{name: "mapped literal is unmapped", rules: []Rule{{IPCIDR: "192.0.2.0/24", Action: "reject"}}, ip: "::ffff:192.0.2.1", kind: Reject},
		{name: "mapped literal allowed is unmapped", rules: []Rule{{IPCIDR: "192.0.2.0/24", Action: "reject"}}, ip: "::ffff:192.0.3.1", kind: Direct, cands: addrs("192.0.3.1")},
		{name: "mapped DNS answer unmapped", rules: []Rule{{IPCIDR: "::ffff:127.0.0.2/128", Action: "reject"}}, host: target, dns: addrs("::ffff:127.0.0.2", "::ffff:127.0.0.1"), kind: Direct, cands: addrs("127.0.0.1"), queries: true},
		// TestDNSRoutingBroadIPv6PrefixValidation: a broad IPv6 prefix never matches IPv4.
		{name: "broad v6 prefix not expanded to v4", rules: []Rule{{IPCIDR: "::ffff:192.0.2.1/80", Action: "reject"}}, ip: "192.0.2.1", kind: Direct, cands: addrs("192.0.2.1")},
		{name: "::/0 does not match v4", rules: []Rule{{IPCIDR: "::/0", Action: "reject"}}, ip: "10.0.0.1", kind: Direct, cands: addrs("10.0.0.1")},
		// Zone IP literal is rejected (candidates()).
		{name: "zone literal rejected", ip: "fe80::1%eth0", kind: Reject},
		{name: "zone literal rejected with rules", rules: []Rule{{IPCIDR: "fe80::/10", Action: "direct"}}, ip: "fe80::1%eth0", kind: Reject},
		// TestDNSRoutingRejectUDPWhitelistAndNoFallback: domain reject queries no DNS; other names pass.
		{name: "domain reject zero DNS", rules: []Rule{{DomainSuffix: "blocked.example", Action: "reject"}}, host: "blocked.example", dns: addrs("127.0.0.1"), kind: Reject, queries: false},
		{name: "unblocked name resolves", rules: []Rule{{DomainSuffix: "blocked.example", Action: "reject"}}, host: "good.example", dns: addrs("127.0.0.1"), kind: Direct, cands: addrs("127.0.0.1"), queries: true},
		// Defaults: no rules = direct with every candidate; literal = itself without DNS.
		{name: "no rules domain", host: "localhost", dns: addrs("127.0.0.1", "::1"), kind: Direct, cands: addrs("127.0.0.1", "::1"), queries: true},
		{name: "no rules literal", ip: "127.0.0.1", kind: Direct, cands: addrs("127.0.0.1")},
		// Per-candidate only allowed, dedupe, all rejected, 16-candidate cap, DNS error.
		{name: "dedupe allowed candidates", rules: []Rule{{IPCIDR: "127.0.0.2/32", Action: "reject"}}, host: target, dns: addrs("127.0.0.2", "127.0.0.1", "127.0.0.1", "::ffff:127.0.0.3"), kind: Direct, cands: addrs("127.0.0.1", "127.0.0.3"), queries: true},
		{name: "all candidates rejected", rules: []Rule{{IPCIDR: "127.0.0.0/8", Action: "reject"}}, host: target, dns: both, kind: Reject, queries: true},
		{name: "dns error with direct outcome returns error", rules: []Rule{{IPCIDR: "127.0.0.2/32", Action: "reject"}}, host: target, dnsErr: errDNSFail, kind: Direct, queries: true, err: true},
		{name: "dns error with domain direct returns error", rules: []Rule{{Domain: target, Action: "direct"}}, host: target, dnsErr: errDNSFail, kind: Direct, queries: true, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := mustEngine(t, Options{Rules: tc.rules}, nil)
			dns := &fakeDNS{ips: tc.dns, err: tc.dnsErr}
			m := Metadata{Network: "tcp", Host: tc.host, Port: 443}
			if tc.ip != "" {
				m = Metadata{Network: "udp", IP: netip.MustParseAddr(tc.ip), Port: 443}
			}
			d, err := e.Decide(context.Background(), m, dns.resolve)
			if (err != nil) != tc.err || tc.err && !errors.Is(err, errDNSFail) {
				t.Fatalf("err=%v want err=%v", err, tc.err)
			}
			if d.Kind != tc.kind || !slices.Equal(d.Candidates, tc.cands) || d.Outbound != "" {
				t.Fatalf("decision %+v want kind=%v cands=%v", d, tc.kind, tc.cands)
			}
			if (dns.calls.Load() > 0) != tc.queries || dns.calls.Load() > 1 {
				t.Fatalf("dns calls=%d want queried=%v", dns.calls.Load(), tc.queries)
			}
		})
	}
	// 16-candidate cap (kernel truncates the resolver answer to 16 before filtering).
	var many []netip.Addr
	for i := 1; i <= 20; i++ {
		many = append(many, netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
	}
	e := mustEngine(t, Options{}, nil)
	d, err := decideHost(t, e, target, 80, &fakeDNS{ips: many})
	if err != nil || d.Kind != Direct || !slices.Equal(d.Candidates, many[:16]) {
		t.Fatal("candidate cap", d, err)
	}
}

// Same accept/reject matrix as TestDNSRoutingStrictSchema's routing entries.
func TestCompatKernelRuleValidation(t *testing.T) {
	good := [][]Rule{
		{{DomainSuffix: "Example.COM.", Action: "reject"}, {IPCIDR: "192.0.2.8/24", Action: "direct"}},
		{{IPCIDR: "::ffff:192.0.2.1/80", Action: "reject"}},
	}
	bad := [][]Rule{
		{{Domain: "x", Action: "proxy"}},
		{{Domain: "x", IPCIDR: "::/0", Action: "reject"}},
		{{Domain: "", Action: "direct"}},
		{{Domain: "*.x", Action: "direct"}},
		{{Domain: "x..y", Action: "direct"}},
		{{IPCIDR: "bad", Action: "direct"}},
		{{IPCIDR: "fe80::/10%eth0", Action: "direct"}},
		{{Domain: "x"}},
		make([]Rule, 1025),
	}
	for i, r := range good {
		o := Options{Rules: r}
		if err := o.Validate(); err != nil {
			t.Fatal("good", i, err)
		}
	}
	o := Options{Rules: good[0]}
	o.Validate()
	if o.Rules[0].DomainSuffix != "example.com" || o.Final != "direct" {
		t.Fatal("normalization", o.Rules[0], o.Final)
	}
	for i, r := range bad {
		o := Options{Rules: r}
		if err := o.Validate(); err == nil {
			t.Fatal("bad accepted", i)
		}
	}
	big := make([]Rule, 1024)
	for i := range big {
		big[i] = Rule{Domain: "a.example", Action: "direct"}
	}
	if err := (&Options{Rules: big}).Validate(); err != nil {
		t.Fatal("1024 rules rejected", err)
	}
}

// ---- reference model: a line-for-line restatement of kernel/routing.go ----

type oldRule struct {
	domain, suffix string
	prefix         netip.Prefix
	isIP           bool
	action         string
}

func (r oldRule) matchDomain(name string) bool {
	return name != "" && (r.domain == name || r.suffix != "" && (name == r.suffix || strings.HasSuffix(name, "."+r.suffix)))
}

var errOldReject = errors.New("old reject")

// oldCandidates mirrors Server.candidates + preDNSReject + routeDirect.
func oldCandidates(rules []oldRule, host string, literal netip.Addr, dns []netip.Addr, dnsErr error) (out []netip.Addr, queried bool, err error) {
	name := ""
	var ips []netip.Addr
	if literal.IsValid() {
		if literal.Zone() != "" {
			return nil, false, errOldReject
		}
		ips = []netip.Addr{literal.Unmap()}
	} else {
		name = host
		for _, r := range rules {
			if r.isIP {
				break
			}
			if r.matchDomain(name) {
				if r.action == "reject" {
					return nil, false, errOldReject
				}
				break
			}
		}
		queried = true
		if dnsErr != nil {
			return nil, true, dnsErr
		}
		ips = dns
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		ip = ip.Unmap()
		direct := true
		for _, r := range rules {
			if r.matchDomain(name) || r.isIP && r.prefix.Contains(ip) {
				direct = r.action == "direct"
				break
			}
		}
		if !seen[ip] && direct {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, queried, errOldReject
	}
	return out, queried, nil
}

// TestCompatRandomizedAgainstKernelModel compares Decide with the kernel's
// current algorithm on random direct/reject rule lists, targets and answers.
func TestCompatRandomizedAgainstKernelModel(t *testing.T) {
	rng := rand.New(rand.NewSource(20261024))
	names := []string{"a.example", "b.a.example", "example", "c.example", "other.test"}
	cidrs := []string{"10.0.0.0/8", "10.1.0.0/16", "::ffff:10.2.0.0/112", "2001:db8::/32", "::/0", "0.0.0.0/0", "::ffff:0:0/96", "::ffff:10.0.0.1/80", "10.1.2.3/32"}
	ips := addrs("10.0.0.1", "10.1.2.3", "10.2.0.5", "192.0.2.1", "2001:db8::1", "::ffff:10.1.0.1", "2001:db9::1", "::ffff:10.2.0.5")
	actions := []string{"direct", "reject"}
	compared, diverged := 0, 0
	for iter := 0; iter < 20000; iter++ {
		var rules []Rule
		var old []oldRule
		for n := rng.Intn(5); n > 0; n-- {
			a := actions[rng.Intn(2)]
			switch rng.Intn(3) {
			case 0:
				d := names[rng.Intn(len(names))]
				rules = append(rules, Rule{Domain: d, Action: a})
				old = append(old, oldRule{domain: d, action: a})
			case 1:
				d := names[rng.Intn(len(names))]
				rules = append(rules, Rule{DomainSuffix: d, Action: a})
				old = append(old, oldRule{suffix: d, action: a})
			default:
				c := cidrs[rng.Intn(len(cidrs))]
				p, _ := parseCIDR(c, false)
				rules = append(rules, Rule{IPCIDR: c, Action: a})
				old = append(old, oldRule{prefix: p, isIP: true, action: a})
			}
		}
		e, err := NewEngine(Options{Rules: rules}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var host string
		var lit netip.Addr
		if rng.Intn(3) == 0 {
			lit = ips[rng.Intn(len(ips))]
		} else {
			host = names[rng.Intn(len(names))]
		}
		var answer []netip.Addr
		for n := 1 + rng.Intn(5); n > 0; n-- {
			answer = append(answer, ips[rng.Intn(len(ips))])
		}
		var dnsErr error
		if rng.Intn(10) == 0 {
			dnsErr = errDNSFail
		}
		dns := &fakeDNS{ips: answer, err: dnsErr}
		d, derr := e.Decide(context.Background(), Metadata{Network: "tcp", Host: host, IP: lit, Port: 80}, dns.resolve)
		want, queried, werr := oldCandidates(old, host, lit, answer, dnsErr)
		ctx := fmt.Sprintf("iter %d rules=%+v host=%q ip=%v dns=%v err=%v: got %+v %v; old %v %v", iter, rules, host, lit, answer, dnsErr, d, derr, want, werr)
		if queried != (dns.calls.Load() == 1) || dns.calls.Load() > 1 {
			t.Fatal("DNS query behaviour differs:", ctx)
		}
		switch {
		case werr == nil:
			if derr != nil || d.Kind != Direct || !slices.Equal(d.Candidates, want) {
				t.Fatal("direct differs:", ctx)
			}
		case errors.Is(werr, errOldReject):
			if derr != nil || d.Kind != Reject {
				t.Fatal("reject differs:", ctx)
			}
		default: // old returned the DNS error
			switch {
			case errors.Is(derr, errDNSFail) && d.Kind == Direct:
			case derr == nil && d.Kind == Reject:
				// Contract rule 4: an IP-rule-dependent reject now resolves
				// to Reject instead of the DNS error; both refuse the target.
				diverged++
			default:
				t.Fatal("dns error differs:", ctx)
			}
		}
		compared++
	}
	t.Logf("compared %d random cases with the kernel model; %d DNS-error cases became Reject (contract rule 4), all others identical", compared, diverged)
}
