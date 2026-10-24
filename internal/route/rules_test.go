package route

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestEachConditionActionAndOutbound(t *testing.T) {
	dir := t.TempDir()
	setPath := filepath.Join(dir, "set.txt")
	os.WriteFile(setPath, []byte("DOMAIN,set.example\nIP-CIDR,203.0.113.0/24\n"), 0o644)
	o := Options{
		Rules: []Rule{
			{Domain: "exact.example", Outbound: "p-domain"},
			{DomainSuffix: "suffix.example", Outbound: "p-suffix"},
			{DomainKeyword: "KeyWord", Outbound: "p-keyword"},
			{SrcIPCIDR: "192.168.50.0/24", Outbound: "p-src"},
			{DstPort: "8443", Outbound: "p-port"},
			{DstPort: "9000-9100", Outbound: "p-range"},
			{Network: "UDP", Outbound: "p-udp"},
			{RuleSet: "s", Outbound: "p-set"},
			{IPCIDR: "198.51.100.0/24", Outbound: "p-cidr"},
			{GeoIP: "private", Outbound: "p-private"},
			{IPCIDR: "100.64.0.0/10", Action: "reject"},
			{IPCIDR: "2001:db8:1::/48", Action: "direct"},
		},
		Final:    "p-final",
		RuleSets: []RuleSetOptions{{Name: "s", Format: "classical", Path: setPath}},
	}
	e := mustEngine(t, o, nil)
	ctx := context.Background()
	cases := []struct {
		m       Metadata
		dns     []netip.Addr
		kind    Kind
		out     string
		cands   []netip.Addr
		queries int64
	}{
		{m: Metadata{Network: "tcp", Host: "exact.example", Port: 80}, kind: Proxy, out: "p-domain"},
		{m: Metadata{Network: "tcp", Host: "a.exact.example", Port: 80}, dns: addrs("8.8.8.8"), kind: Proxy, out: "p-final", queries: 1},
		{m: Metadata{Network: "tcp", Host: "suffix.example", Port: 80}, kind: Proxy, out: "p-suffix"},
		{m: Metadata{Network: "tcp", Host: "x.y.suffix.example", Port: 80}, kind: Proxy, out: "p-suffix"},
		{m: Metadata{Network: "tcp", Host: "my-keyword-site.test", Port: 80}, kind: Proxy, out: "p-keyword"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 80, Source: netip.MustParseAddr("::ffff:192.168.50.7")}, kind: Proxy, out: "p-src"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 8443}, kind: Proxy, out: "p-port"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 9050}, kind: Proxy, out: "p-range"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 9101}, dns: addrs("8.8.8.8"), kind: Proxy, out: "p-final", queries: 1},
		{m: Metadata{Network: "udp", Host: "x.test", Port: 53}, kind: Proxy, out: "p-udp"},
		{m: Metadata{Network: "tcp", Host: "set.example", Port: 80}, kind: Proxy, out: "p-set"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 80}, dns: addrs("203.0.113.9"), kind: Proxy, out: "p-set", queries: 1},
		{m: Metadata{Network: "tcp", IP: netip.MustParseAddr("203.0.113.9"), Port: 80}, kind: Proxy, out: "p-set"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 80}, dns: addrs("198.51.100.1"), kind: Proxy, out: "p-cidr", queries: 1},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 80}, dns: addrs("10.1.1.1"), kind: Proxy, out: "p-private", queries: 1},
		{m: Metadata{Network: "tcp", IP: netip.MustParseAddr("fd00::1"), Port: 80}, kind: Proxy, out: "p-private"},
		{m: Metadata{Network: "tcp", Host: "x.test", Port: 80}, dns: addrs("100.64.0.1"), kind: Proxy, out: "p-private", queries: 1}, // private before reject
		{m: Metadata{Network: "tcp", IP: netip.MustParseAddr("2001:db8:1::5"), Port: 80}, kind: Proxy, out: "p-private"},             // 2001:db8::/32 is documentation = private
		{m: Metadata{Network: "tcp", IP: netip.MustParseAddr("8.8.8.8"), Port: 80}, kind: Proxy, out: "p-final"},
	}
	for i, tc := range cases {
		dns := &fakeDNS{ips: tc.dns}
		d, err := e.Decide(ctx, tc.m, dns.resolve)
		if err != nil || d.Kind != tc.kind || d.Outbound != tc.out || !slices.Equal(d.Candidates, tc.cands) || dns.calls.Load() != tc.queries {
			t.Fatalf("case %d %+v: got %+v err=%v dns=%d", i, tc.m, d, err, dns.calls.Load())
		}
	}
	// Actions: direct returns candidates, reject none; outbound "direct" equals action direct.
	e2 := mustEngine(t, Options{Rules: []Rule{
		{IPCIDR: "100.64.0.0/10", Action: "reject"},
		{Domain: "d.example", Outbound: "direct"},
		{Domain: "r.example", Outbound: "reject"},
	}, Final: "reject"}, nil)
	// The IP rule comes first, so the domain rule is evaluated per candidate (kernel semantics).
	if d, _ := decideHost(t, e2, "d.example", 1, &fakeDNS{ips: addrs("1.1.1.1", "100.64.0.1")}); d.Kind != Direct || !slices.Equal(d.Candidates, addrs("1.1.1.1")) {
		t.Fatal("outbound direct", d)
	}
	if d, _ := decideHost(t, e2, "r.example", 1, &fakeDNS{}); d.Kind != Reject {
		t.Fatal("outbound reject", d)
	}
	if d, _ := decideHost(t, e2, "z.example", 1, &fakeDNS{ips: addrs("1.1.1.1")}); d.Kind != Reject {
		t.Fatal("final reject", d)
	}
	if d := decideIP(t, e2, "100.64.0.1", 1); d.Kind != Reject {
		t.Fatal("ip reject", d)
	}
}

func TestNoResolveAndDNSFailure(t *testing.T) {
	// no_resolve: a domain target never triggers DNS for the rule; an IP target matches it.
	e := mustEngine(t, Options{Rules: []Rule{
		{IPCIDR: "10.0.0.0/8", NoResolve: true, Outbound: "lan"},
		{GeoIP: "private", NoResolve: true, Outbound: "priv"},
	}, Final: "proxy"}, nil)
	dns := &fakeDNS{ips: addrs("10.0.0.1")}
	if d, err := decideHost(t, e, "internal.example", 80, dns); err != nil || d.Kind != Proxy || d.Outbound != "proxy" || dns.calls.Load() != 0 {
		t.Fatal("no_resolve resolved", d, err, dns.calls.Load())
	}
	if d := decideIP(t, e, "10.2.3.4", 80); d.Outbound != "lan" {
		t.Fatal("no_resolve literal", d)
	}
	if d := decideIP(t, e, "192.168.1.1", 80); d.Outbound != "priv" {
		t.Fatal("no_resolve geoip literal", d)
	}
	// Once another rule caused resolution, later no_resolve rules see the IP.
	e = mustEngine(t, Options{Rules: []Rule{
		{IPCIDR: "203.0.113.0/24", Action: "reject"},
		{IPCIDR: "10.0.0.0/8", NoResolve: true, Outbound: "lan"},
	}, Final: "proxy"}, nil)
	dns = &fakeDNS{ips: addrs("10.0.0.1")}
	if d, _ := decideHost(t, e, "n.example", 80, dns); d.Outbound != "lan" || dns.calls.Load() != 1 {
		t.Fatal("resolved IP for later no_resolve", d)
	}

	// DNS failure: IP rules do not match; non-direct outcomes still apply.
	fail := &fakeDNS{err: errDNSFail}
	e = mustEngine(t, Options{Rules: []Rule{
		{IPCIDR: "10.0.0.0/8", Action: "direct"},
		{DomainSuffix: "p.example", Outbound: "P"},
		{DomainSuffix: "r.example", Action: "reject"},
	}, Final: "F"}, nil)
	if d, err := decideHost(t, e, "x.p.example", 80, fail); err != nil || d.Kind != Proxy || d.Outbound != "P" {
		t.Fatal("dns failure proxy", d, err)
	}
	if d, err := decideHost(t, e, "x.r.example", 80, fail); err != nil || d.Kind != Reject {
		t.Fatal("dns failure reject", d, err)
	}
	if d, err := decideHost(t, e, "other.example", 80, fail); err != nil || d.Kind != Proxy || d.Outbound != "F" {
		t.Fatal("dns failure final proxy", d, err)
	}
	e = mustEngine(t, Options{Rules: []Rule{{IPCIDR: "10.0.0.0/8", Outbound: "P"}}}, nil)
	if d, err := decideHost(t, e, "other.example", 80, fail); !errors.Is(err, errDNSFail) || d.Kind != Direct {
		t.Fatal("dns failure final direct must error", d, err)
	}
	if _, err := decideHost(t, e, "other.example", 80, &fakeDNS{}); !errors.Is(err, ErrNoAddress) {
		t.Fatal("empty answer", err)
	}
	if _, err := e.Decide(context.Background(), Metadata{Host: "x.example"}, nil); err == nil {
		t.Fatal("nil resolver")
	}
}

func TestFirstNonRejectCandidateDecides(t *testing.T) {
	e := mustEngine(t, Options{Rules: []Rule{
		{IPCIDR: "10.0.0.1/32", Action: "reject"},
		{IPCIDR: "10.0.0.2/32", Outbound: "A"},
		{IPCIDR: "10.0.0.3/32", Action: "direct"},
		{IPCIDR: "10.0.0.4/32", Outbound: "B"},
	}}, nil)
	cases := []struct {
		dns   []netip.Addr
		kind  Kind
		out   string
		cands []netip.Addr
	}{
		{addrs("10.0.0.1", "10.0.0.2", "10.0.0.3"), Proxy, "A", nil},
		{addrs("10.0.0.1", "10.0.0.3", "10.0.0.2", "10.0.0.9"), Direct, "", addrs("10.0.0.3", "10.0.0.9")},
		{addrs("10.0.0.4", "10.0.0.2"), Proxy, "B", nil},
		{addrs("10.0.0.1", "10.0.0.1"), Reject, "", nil},
	}
	for i, tc := range cases {
		dns := &fakeDNS{ips: tc.dns}
		d, err := decideHost(t, e, "multi.example", 443, dns)
		if err != nil || d.Kind != tc.kind || d.Outbound != tc.out || !slices.Equal(d.Candidates, tc.cands) || dns.calls.Load() != 1 {
			t.Fatalf("case %d: %+v %v", i, d, err)
		}
	}
}

func TestRuleSetDomainPartAvoidsDNS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mixed.txt")
	os.WriteFile(p, []byte("DOMAIN-SUFFIX,ads.example\nIP-CIDR,203.0.113.0/24\nIP-CIDR,198.51.100.0/24,no-resolve\nDST-PORT,6881-6889\n"), 0o644)
	e := mustEngine(t, Options{Rules: []Rule{{RuleSet: "m", Action: "reject"}}, RuleSets: []RuleSetOptions{{Name: "m", Format: "classical", Path: p}}}, nil)
	dns := &fakeDNS{ips: addrs("203.0.113.1")}
	if d, _ := decideHost(t, e, "x.ads.example", 80, dns); d.Kind != Reject || dns.calls.Load() != 0 {
		t.Fatal("domain part", d, dns.calls.Load())
	}
	if d, _ := decideHost(t, e, "x.test", 6885, dns); d.Kind != Reject || dns.calls.Load() != 0 {
		t.Fatal("port part", d)
	}
	if d, _ := decideHost(t, e, "x.test", 80, dns); d.Kind != Reject || dns.calls.Load() != 1 {
		t.Fatal("ip part", d)
	}
	if d := decideIP(t, e, "198.51.100.7", 80); d.Kind != Reject {
		t.Fatal("no-resolve entry on literal", d)
	}
	// Rule-level no_resolve: the IP part never triggers DNS.
	e = mustEngine(t, Options{Rules: []Rule{{RuleSet: "m", NoResolve: true, Action: "reject"}}, RuleSets: []RuleSetOptions{{Name: "m", Format: "classical", Path: p}}}, nil)
	dns = &fakeDNS{ips: addrs("203.0.113.1")}
	if d, _ := decideHost(t, e, "x.test", 80, dns); d.Kind != Direct || dns.calls.Load() != 1 || !slices.Equal(d.Candidates, addrs("203.0.113.1")) {
		t.Fatal("rule no_resolve", d) // the single DNS call is for direct dialing
	}
	// A set whose IP entries are all no-resolve does not trigger DNS for rule matching.
	p2 := filepath.Join(t.TempDir(), "nr.txt")
	os.WriteFile(p2, []byte("IP-CIDR,203.0.113.0/24,no-resolve\n"), 0o644)
	e = mustEngine(t, Options{Rules: []Rule{{RuleSet: "n", Action: "reject"}}, Final: "P", RuleSets: []RuleSetOptions{{Name: "n", Format: "classical", Path: p2}}}, nil)
	dns = &fakeDNS{ips: addrs("203.0.113.1")}
	if d, _ := decideHost(t, e, "x.test", 80, dns); d.Kind != Proxy || dns.calls.Load() != 0 {
		t.Fatal("entry no-resolve", d, dns.calls.Load())
	}
}

func TestValidateStrict(t *testing.T) {
	dir := t.TempDir()
	set := RuleSetOptions{Name: "s", Format: "domain", Path: filepath.Join(dir, "s.txt")}
	geo := &GeoIPOptions{Path: filepath.Join(dir, "g.mmdb")}
	bad := []Options{
		{Rules: []Rule{{Domain: "a.example"}}},
		{Rules: []Rule{{Domain: "a.example", Action: "direct", Outbound: "x"}}},
		{Rules: []Rule{{Domain: "a.example", Action: "DIRECT"}}},
		{Rules: []Rule{{Domain: "a.example", NoResolve: true, Action: "direct"}}},
		{Rules: []Rule{{SrcIPCIDR: "10.0.0.0/8", NoResolve: true, Action: "direct"}}},
		{Rules: []Rule{{DstPort: "0", Action: "direct"}}},
		{Rules: []Rule{{DstPort: "65536", Action: "direct"}}},
		{Rules: []Rule{{DstPort: "90-80", Action: "direct"}}},
		{Rules: []Rule{{DstPort: "80,443", Action: "direct"}}},
		{Rules: []Rule{{DstPort: " 80", Action: "direct"}}},
		{Rules: []Rule{{Network: "icmp", Action: "direct"}}},
		{Rules: []Rule{{GeoIP: "CHN", Action: "direct"}}, GeoIP: geo},
		{Rules: []Rule{{GeoIP: "C1", Action: "direct"}}, GeoIP: geo},
		{Rules: []Rule{{GeoIP: "CN", Action: "direct"}}}, // needs geoip block
		{Rules: []Rule{{RuleSet: "missing", Action: "direct"}}},
		{Rules: []Rule{{DomainKeyword: "a b", Action: "direct"}}},
		{Rules: []Rule{{Domain: "a.example", Outbound: "has space"}}},
		{Final: "bad name"},
		{RuleSets: []RuleSetOptions{set, set}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "yaml", Path: "x"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain"}}},
		{RuleSets: []RuleSetOptions{{Name: "", Format: "domain", Path: "x"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "http://h/x"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "https://user:pw@h/x"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "https:///x"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "https://h:0/x"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "https://h/x#f"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "https://h/x", Interval: outbound.Duration(59e9)}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", Interval: outbound.Duration(3600e9)}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", Via: "p"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", URL: "https://h/x", Via: "reject"}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", MaxBytes: 64<<20 + 1}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", MaxBytes: -1}}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "x", MaxBytes: 100}}},
		{GeoIP: &GeoIPOptions{}},
		{GeoIP: &GeoIPOptions{Path: "g", MaxBytes: 256<<20 + 1}},
		{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "same"}}, GeoIP: &GeoIPOptions{Path: "same"}},
	}
	many := Options{}
	for i := 0; i < 33; i++ {
		many.RuleSets = append(many.RuleSets, RuleSetOptions{Name: "s" + itoa(i), Format: "domain", Path: "p" + itoa(i)})
	}
	bad = append(bad, many)
	for i, o := range bad {
		if err := o.Validate(); err == nil {
			t.Fatalf("bad options %d accepted: %+v", i, o)
		}
	}
	many.RuleSets = many.RuleSets[:32]
	if err := many.Validate(); err != nil {
		t.Fatal("32 rule sets", err)
	}
	good := Options{
		Rules: []Rule{
			{GeoIP: "cn", Outbound: "g1"},
			{GeoIP: "PRIVATE", NoResolve: true, Action: "direct"},
			{Network: "TCP", Outbound: "g2"},
			{DstPort: "1-65535", Outbound: "g1"},
			{RuleSet: "s", NoResolve: true, Outbound: "direct"},
		},
		Final:    "g3",
		RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: "a", URL: "https://h.example:8443/x?y=1", Via: "g4"}, {Name: "t", Format: "ipcidr", Path: "b", URL: "https://h/x", MaxBytes: 1024}},
		GeoIP:    &GeoIPOptions{Path: "g", URL: "https://[::1]/c.mmdb", Via: "g1"},
	}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if good.Rules[0].GeoIP != "CN" || good.Rules[1].GeoIP != "private" || good.Rules[2].Network != "tcp" || good.Rules[4].Action != "direct" || good.Rules[4].Outbound != "" {
		t.Fatal("normalization", good.Rules)
	}
	if good.RuleSets[0].Interval.Value() != defaultInterval || good.RuleSets[1].Via != "direct" || good.RuleSets[0].MaxBytes != defaultSetBytes || good.GeoIP.MaxBytes != defaultGeoBytes || good.GeoIP.Interval.Value() != defaultInterval {
		t.Fatal("defaults", good.RuleSets, *good.GeoIP)
	}
	if got := good.ReferencedOutbounds(); !slices.Equal(got, []string{"g1", "g2", "g3", "g4"}) {
		t.Fatal("referenced outbounds", got)
	}
	// JSON field names follow the contract.
	var o Options
	j := `{"rules":[{"domain":"a","domain_suffix":"b","domain_keyword":"c","ip_cidr":"d","src_ip_cidr":"e","geoip":"f","dst_port":"g","network":"h","rule_set":"i","no_resolve":true,"action":"j","outbound":"k"}],"final":"l","rule_sets":[{"name":"m","format":"n","path":"o","url":"p","interval":"1h","via":"q","max_bytes":5}],"geoip":{"path":"r","url":"s","interval":"2h","via":"t","max_bytes":6}}`
	dec := json.NewDecoder(strings.NewReader(j))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		t.Fatal(err)
	}
	r := o.Rules[0]
	if r.Domain != "a" || r.DomainSuffix != "b" || r.DomainKeyword != "c" || r.IPCIDR != "d" || r.SrcIPCIDR != "e" || r.GeoIP != "f" || r.DstPort != "g" || r.Network != "h" || r.RuleSet != "i" || !r.NoResolve || r.Action != "j" || r.Outbound != "k" || o.Final != "l" ||
		o.RuleSets[0].Interval.Value().String() != "1h0m0s" || o.RuleSets[0].MaxBytes != 5 || o.GeoIP.Via != "t" || o.GeoIP.MaxBytes != 6 {
		t.Fatalf("json mapping %+v", o)
	}
	// NewEngine validates and requires dial for url sources.
	if _, err := NewEngine(Options{Rules: []Rule{{Domain: "x"}}}, nil, nil); err == nil {
		t.Fatal("NewEngine skipped validation")
	}
	if _, err := NewEngine(Options{RuleSets: []RuleSetOptions{{Name: "s", Format: "domain", Path: filepath.Join(dir, "u"), URL: "https://h/x"}}}, nil, nil); err == nil {
		t.Fatal("url without dial")
	}
}

func TestIPSetAgainstLinearPrefixes(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for round := 0; round < 200; round++ {
		var s ipSet
		var ps []netip.Prefix
		for n := rng.Intn(40); n > 0; n-- {
			var p netip.Prefix
			if rng.Intn(2) == 0 {
				var b [4]byte
				rng.Read(b[:])
				b[0] = byte(rng.Intn(4)) // dense area to force overlaps
				p = netip.PrefixFrom(netip.AddrFrom4(b), rng.Intn(33)).Masked()
			} else {
				var b [16]byte
				rng.Read(b[:])
				b[0], b[1] = 0x20, byte(rng.Intn(3))
				p = netip.PrefixFrom(netip.AddrFrom16(b), rng.Intn(129)).Masked()
			}
			s.add(p)
			ps = append(ps, p)
		}
		s.build()
		for k := 0; k < 300; k++ {
			var ip netip.Addr
			if rng.Intn(2) == 0 {
				var b [4]byte
				rng.Read(b[:])
				b[0] = byte(rng.Intn(5))
				ip = netip.AddrFrom4(b)
			} else {
				var b [16]byte
				rng.Read(b[:])
				b[0], b[1] = 0x20, byte(rng.Intn(4))
				ip = netip.AddrFrom16(b)
			}
			want := false
			for _, p := range ps {
				want = want || p.Contains(ip)
			}
			if s.contains(ip) != want {
				t.Fatalf("ipSet mismatch %v prefixes=%v", ip, ps)
			}
		}
	}
	var all ipSet
	all.add(netip.MustParsePrefix("0.0.0.0/0"))
	all.add(netip.MustParsePrefix("::/0"))
	all.add(netip.MustParsePrefix("255.255.255.255/32"))
	all.build()
	if !all.contains(netip.MustParseAddr("255.255.255.255")) || !all.contains(netip.MustParseAddr("ffff::1")) || len(all.v4) != 1 || len(all.v6) != 1 {
		t.Fatal("full ranges", all)
	}
}
