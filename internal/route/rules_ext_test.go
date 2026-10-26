package route

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- minimal protobuf writer for geosite.dat fixtures ----

func pbKey(f, w int) []byte { return binary.AppendUvarint(nil, uint64(f<<3|w)) }
func pbBytes(f int, b []byte) []byte {
	out := pbKey(f, 2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}
func pbVarint(f int, v uint64) []byte { return binary.AppendUvarint(pbKey(f, 0), v) }

type siteDom struct {
	typ   int // 0 plain(keyword) 1 regex 2 domain 3 full
	value string
	attrs []string
}

func buildGeosite(cats map[string][]siteDom) []byte {
	var list []byte
	for name, doms := range cats {
		site := pbBytes(1, []byte(strings.ToUpper(name)))
		for _, d := range doms {
			var dm []byte
			if d.typ != 0 {
				dm = append(dm, pbVarint(1, uint64(d.typ))...)
			}
			dm = append(dm, pbBytes(2, []byte(d.value))...)
			for _, a := range d.attrs {
				attr := append(pbBytes(1, []byte(a)), pbVarint(2, 1)...)
				dm = append(dm, pbBytes(3, attr)...)
			}
			site = append(site, pbBytes(2, dm)...)
		}
		list = append(list, pbBytes(1, site)...)
	}
	return list
}

func testGeosite() []byte {
	return buildGeosite(map[string][]siteDom{
		"google": {
			{2, "google.com", nil},
			{2, "google.cn", []string{"cn"}},
			{3, "full.google.example", []string{"ads"}},
			{0, "gstatic", nil},
			{1, `^www\.g[0-9]+\.example$`, nil},
		},
		"empty": nil,
	})
}

// ASN fixture: GeoLite2-ASN record layout.
func testASNDB(t *testing.T) []byte {
	return buildMMDB(t, map[string]int{
		"1.1.1.0/24":     0,
		"8.8.8.0/24":     1,
		"2606:4700::/32": 0,
		"10.20.0.0/16":   2,
	}, []mmMap{
		{{"autonomous_system_number", mmU32(13335)}, {"autonomous_system_organization", "CLOUDFLARENET"}},
		{{"autonomous_system_number", mmU32(15169)}, {"autonomous_system_organization", "GOOGLE"}},
		{{"autonomous_system_number", mmU32(64512)}, {"autonomous_system_organization", "PRIVATE"}},
	})
}

type extCase struct {
	name string
	m    Metadata
	want string // outbound or "" for final(direct)
}

func runCases(t *testing.T, e *Engine, dns *fakeDNS, cases []extCase) {
	t.Helper()
	for _, c := range cases {
		if c.m.Network == "" {
			c.m.Network = "tcp"
		}
		if c.m.Port == 0 {
			c.m.Port = 443
		}
		if dns == nil {
			dns = &fakeDNS{ips: addrs("192.0.2.200")}
		}
		res := Resolver(dns.resolve)
		d, err := e.Decide(context.Background(), c.m, res)
		if err != nil && !errors.Is(err, errDNSFail) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if d.Outbound != c.want || c.want == "" && d.Kind != Direct {
			t.Fatalf("%s: got %+v want %q", c.name, d, c.want)
		}
	}
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestNewRuleTypesHitAndMiss(t *testing.T) {
	dir := t.TempDir()
	gs := filepath.Join(dir, "geosite.dat")
	os.WriteFile(gs, testGeosite(), 0o644)
	asn := filepath.Join(dir, "asn.mmdb")
	os.WriteFile(asn, testASNDB(t), 0o644)
	geo := filepath.Join(dir, "country.mmdb")
	os.WriteFile(geo, testMMDB(t), 0o644)
	ev := &eventLog{}
	e := mustEngine(t, Options{
		Rules: []Rule{
			{DomainRegex: `^api[0-9]+\.regex\.example$`, Outbound: "regex"},
			{DomainWildcard: "*.wild?.example", Outbound: "wild"},
			{Geosite: "google@cn", Outbound: "gs-cn"},
			{Geosite: "google@!cn", Outbound: "gs-notcn"},
			{IPSuffix: "0.0.0.53/8", Outbound: "suffix"},
			{IPASN: "AS13335", Outbound: "asn", NoResolve: true},
			{SrcIPASN: "64512", Outbound: "srcasn"},
			{SrcGeoIP: "JP", Outbound: "srcjp"},
			{SrcPort: "40000-40010,50000", Outbound: "srcport"},
			{InPort: "8388", Outbound: "inport"},
			{InName: "edge", Outbound: "inname"},
			{InType: "trojan", Outbound: "intype"},
			{Protocol: "quic", Outbound: "quic"},
			{DstPort: "1000-2000,3000,4000-4000", Outbound: "port"},
		},
		Geosite: &GeoIPOptions{Path: gs},
		ASN:     &GeoIPOptions{Path: asn},
		GeoIP:   &GeoIPOptions{Path: geo},
	}, ev)
	if ev.count("geosite_loaded") != 1 || ev.count("asn_loaded") != 1 {
		t.Fatal(ev.all())
	}
	src := ip("192.0.2.1")
	runCases(t, e, nil, []extCase{
		{"regex hit", Metadata{Host: "api12.regex.example", Source: src}, "regex"},
		{"regex miss", Metadata{Host: "api.regex.example", Source: src}, ""},
		{"wildcard hit", Metadata{Host: "a.b.wild1.example", Source: src}, "wild"},
		{"wildcard miss ?", Metadata{Host: "x.wild12.example", Source: src}, ""},
		{"wildcard miss apex", Metadata{Host: "wild1.example", Source: src}, ""},
		{"geosite @cn hit", Metadata{Host: "www.google.cn", Source: src}, "gs-cn"},
		{"geosite !cn domain", Metadata{Host: "mail.google.com", Source: src}, "gs-notcn"},
		{"geosite !cn full", Metadata{Host: "full.google.example", Source: src}, "gs-notcn"},
		{"geosite full miss sub", Metadata{Host: "a.full.google.example", Source: src}, ""},
		{"geosite keyword", Metadata{Host: "x.gstatic.net", Source: src}, "gs-notcn"},
		{"geosite regex", Metadata{Host: "www.g7.example", Source: src}, "gs-notcn"},
		{"geosite miss", Metadata{Host: "example.org", Source: src}, ""},
		{"ip suffix hit", Metadata{IP: ip("9.1.2.53"), Source: src}, "suffix"},
		{"ip suffix miss", Metadata{IP: ip("9.1.2.54"), Source: src}, ""},
		{"asn hit v4", Metadata{IP: ip("1.1.1.1"), Source: src}, "asn"},
		{"asn hit v6", Metadata{IP: ip("2606:4700::1"), Source: src}, "asn"},
		{"asn miss", Metadata{IP: ip("8.8.8.8"), Source: src}, ""},
		{"src asn hit", Metadata{IP: ip("9.9.9.9"), Source: ip("10.20.1.1")}, "srcasn"},
		{"src geoip hit", Metadata{IP: ip("9.9.9.9"), Source: ip("133.5.5.5")}, "srcjp"},
		{"src geoip miss", Metadata{IP: ip("9.9.9.9"), Source: ip("1.0.1.1")}, ""},
		{"src port lo", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 40000}, "srcport"},
		{"src port hi", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 40010}, "srcport"},
		{"src port list", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 50000}, "srcport"},
		{"src port below", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 39999}, ""},
		{"src port above", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 40011}, ""},
		{"in port", Metadata{IP: ip("9.9.9.9"), Source: src, InPort: 8388}, "inport"},
		{"in port miss", Metadata{IP: ip("9.9.9.9"), Source: src, InPort: 8389}, ""},
		{"in name", Metadata{IP: ip("9.9.9.9"), Source: src, InName: "edge"}, "inname"},
		{"in name miss", Metadata{IP: ip("9.9.9.9"), Source: src, InName: "edge2"}, ""},
		{"in type", Metadata{IP: ip("9.9.9.9"), Source: src, InType: "trojan"}, "intype"},
		{"in type miss", Metadata{IP: ip("9.9.9.9"), Source: src, InType: "vless"}, ""},
		{"protocol", Metadata{IP: ip("9.9.9.9"), Source: src, Protocol: "quic", Network: "udp"}, "quic"},
		{"protocol miss", Metadata{IP: ip("9.9.9.9"), Source: src, Protocol: "tls"}, ""},
		{"port 999", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 999}, ""},
		{"port 1000", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 1000}, "port"},
		{"port 2000", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 2000}, "port"},
		{"port 2001", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 2001}, ""},
		{"port 2999", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 2999}, ""},
		{"port 3000", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 3000}, "port"},
		{"port 3001", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 3001}, ""},
		{"port 4000", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 4000}, "port"},
		// A sniffed domain is used by the domain conditions of an IP target.
		{"sniffed host", Metadata{IP: ip("9.9.9.9"), Source: src, SniffHost: "api7.regex.example"}, "regex"},
		{"sniffed geosite", Metadata{IP: ip("9.9.9.9"), Source: src, SniffHost: "maps.google.cn"}, "gs-cn"},
	})
	// ASN with resolution: the domain is resolved for an ASN rule without no_resolve.
	e2 := mustEngine(t, Options{
		Rules: []Rule{{IPASN: "15169", Outbound: "g"}},
		ASN:   &GeoIPOptions{Path: asn},
	}, nil)
	dns := &fakeDNS{ips: addrs("8.8.8.8")}
	if d, _ := decideHost(t, e2, "dns.google", 443, dns); d.Outbound != "g" || dns.calls.Load() != 1 {
		t.Fatal(d)
	}
	// no_resolve never resolves on its own...
	e3 := mustEngine(t, Options{
		Rules: []Rule{{IPASN: "13335", Outbound: "cf", NoResolve: true}},
		ASN:   &GeoIPOptions{Path: asn},
	}, nil)
	dns = &fakeDNS{ips: addrs("1.1.1.1")}
	if d, _ := decideHost(t, e3, "one.example", 443, dns); d.Kind != Direct || dns.calls.Load() != 1 {
		t.Fatal(d, dns.calls.Load()) // the one call is for the final's direct candidates
	}
	// ...but matches an address resolved for an earlier rule (ip_suffix here).
	dns = &fakeDNS{ips: addrs("1.1.1.1")}
	if d, _ := decideHost(t, e, "one.example", 443, dns); d.Outbound != "asn" || dns.calls.Load() != 1 {
		t.Fatal(d, dns.calls.Load())
	}
}

func TestPortListBoundariesAndValidation(t *testing.T) {
	for in, want := range map[string]string{
		"80":                "80",
		"1-65535":           "1-65535",
		"443,80":            "443,80",
		"1000-2000/3000":    "1000-2000,3000",
		"65535":             "65535",
		"8080-8080":         "8080",
		"1,2,3,4,5,6,7,8,9": "1,2,3,4,5,6,7,8,9",
	} {
		got, ok := normPorts(in)
		if !ok || got != want {
			t.Fatalf("%q: %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "0", "65536", "2-1", "1-", "-1", "a", "1,,2", "1, 2", "1-2-3", " 1"} {
		if _, ok := normPorts(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	l, _ := ParsePorts("1000-2000,3000")
	for p, want := range map[uint16]bool{999: false, 1000: true, 1500: true, 2000: true, 2001: false, 3000: true, 3001: false, 0: false, 65535: false} {
		if l.Contains(p) != want {
			t.Fatal(p)
		}
	}
}

func TestLogicalNestingAndShortCircuit(t *testing.T) {
	e := mustEngine(t, Options{Rules: []Rule{
		// AND(domain_suffix, OR(port 443, NOT(network tcp)))
		{And: []Rule{{DomainSuffix: "a.example"}, {Or: []Rule{{DstPort: "443"}, {Not: &Rule{Network: "tcp"}}}}}, Outbound: "and-or-not"},
		// AND(port 22, ip_cidr): the first false condition stops; no DNS.
		{And: []Rule{{DstPort: "22"}, {IPCIDR: "10.0.0.0/8"}}, Outbound: "ssh10"},
		// OR(domain, ip_cidr): a true domain condition decides without DNS.
		{Or: []Rule{{Domain: "or.example"}, {IPCIDR: "10.0.0.0/8"}}, Outbound: "or"},
		// NOT(ip_cidr) needs the IP.
		{Not: &Rule{IPCIDR: "203.0.113.0/24"}, Outbound: "not-doc"},
	}}, nil)
	for _, c := range []struct {
		host    string
		ip      string
		network string
		port    uint16
		dns     []string
		want    string
		queries int64
	}{
		{"x.a.example", "", "tcp", 443, nil, "and-or-not", 0},
		{"x.a.example", "", "udp", 80, nil, "and-or-not", 0},
		{"x.a.example", "", "tcp", 80, []string{"203.0.113.9"}, "", 1},
		{"or.example", "", "tcp", 80, nil, "or", 0},
		{"b.example", "", "tcp", 80, []string{"198.51.100.1"}, "not-doc", 1},
		{"b.example", "", "tcp", 22, []string{"10.1.1.1"}, "ssh10", 1},
		{"", "10.1.1.1", "tcp", 22, nil, "ssh10", 0},
		{"", "203.0.113.1", "tcp", 22, nil, "", 0},
		{"", "198.51.100.1", "tcp", 22, nil, "not-doc", 0},
	} {
		dns := &fakeDNS{ips: addrs(c.dns...)}
		m := Metadata{Network: c.network, Host: c.host, Port: c.port}
		if c.ip != "" {
			m.IP, m.Host = ip(c.ip), ""
		}
		d, err := e.Decide(context.Background(), m, dns.resolve)
		if err != nil {
			t.Fatal(c, err)
		}
		if d.Outbound != c.want {
			t.Fatalf("%+v: got %+v", c, d)
		}
		// A decision before DNS (domain-only) must not have queried.
		if c.queries == 0 && c.want != "" && dns.calls.Load() != 0 {
			t.Fatalf("%+v: unexpected DNS", c)
		}
	}
	// Short circuit in AND: the second condition is a rule set that would
	// need DNS; the first is false, so the decision is the final with only
	// the final's own resolution (none for an IP target).
	e2 := mustEngine(t, Options{Rules: []Rule{
		{And: []Rule{{Network: "udp"}, {IPCIDR: "10.0.0.0/8"}}, Outbound: "x"},
		{Domain: "z.example", Outbound: "z"},
	}}, nil)
	dns := &fakeDNS{ips: addrs("10.0.0.1")}
	if d, _ := decideHost(t, e2, "z.example", 80, dns); d.Outbound != "z" || dns.calls.Load() != 0 {
		t.Fatal("AND short circuit before DNS", d, dns.calls.Load())
	}
	// Validation: depth, empty and/or, action inside a sub-condition.
	deep := Rule{Domain: "a.example"}
	for i := 0; i < 9; i++ {
		deep = Rule{Not: &Rule{Not: nil, And: []Rule{deep, {Network: "tcp"}}}}
	}
	for i, bad := range []Rule{
		{And: []Rule{{Domain: "a.example"}}, Action: "direct"},
		{Or: []Rule{}, Action: "direct"},
		{And: []Rule{{Domain: "a.example", Action: "reject"}, {Network: "tcp"}}, Action: "direct"},
		{Not: &Rule{}, Action: "direct"},
		{And: []Rule{{Domain: "a.example", Network: "tcp"}, {Network: "tcp"}}, Action: "direct"},
		{Not: deep.Not, Action: "direct"},
	} {
		o := Options{Rules: []Rule{bad}}
		if o.Validate() == nil {
			t.Fatalf("bad logical %d accepted", i)
		}
	}
}

func TestClassicalAllTypesAndLogical(t *testing.T) {
	dir := t.TempDir()
	gs := filepath.Join(dir, "geosite.dat")
	os.WriteFile(gs, testGeosite(), 0o644)
	asn := filepath.Join(dir, "asn.mmdb")
	os.WriteFile(asn, testASNDB(t), 0o644)
	set := filepath.Join(dir, "c.list")
	os.WriteFile(set, []byte(strings.Join([]string{
		"DOMAIN-REGEX,^re[0-9]\\.example$",
		"DOMAIN-WILDCARD,*.wc.example",
		"GEOSITE,google@cn",
		"IP-SUFFIX,0.0.0.77/8,no-resolve",
		"IP-ASN,13335,no-resolve",
		"SRC-IP-ASN,64512",
		"SRC-PORT,61000-61001",
		"IN-PORT,7000",
		"IN-NAME,lab",
		"IN-TYPE,ss",
		"PROTOCOL,http",
		"DST-PORT,9000-9001/9100",
		"AND,((DOMAIN-SUFFIX,and.example),(NOT,((DST-PORT,80))))",
		"OR,((DOMAIN,o1.example),(AND,((DOMAIN,o2.example),(NETWORK,udp))))",
	}, "\n")), 0o644)
	ev := &eventLog{}
	e := mustEngine(t, Options{
		Rules:    []Rule{{RuleSet: "c", Outbound: "set"}},
		RuleSets: []RuleSetOptions{{Name: "c", Format: "classical", Path: set}},
		Geosite:  &GeoIPOptions{Path: gs},
		ASN:      &GeoIPOptions{Path: asn},
	}, ev)
	if ev.count("rule_set_loaded", "name", "c", "entries", "14", "skipped", "0") != 1 {
		t.Fatal(ev.all())
	}
	src := ip("192.0.2.1")
	runCases(t, e, nil, []extCase{
		{"regex", Metadata{Host: "re5.example", Source: src}, "set"},
		{"regex miss", Metadata{Host: "re55.example", Source: src}, ""},
		{"wildcard", Metadata{Host: "x.wc.example", Source: src}, "set"},
		{"geosite", Metadata{Host: "google.cn", Source: src}, "set"},
		{"geosite miss attr", Metadata{Host: "google.com", Source: src}, ""},
		{"ip suffix", Metadata{IP: ip("5.6.7.77"), Source: src}, "set"},
		{"asn", Metadata{IP: ip("1.1.1.9"), Source: src}, "set"},
		{"src asn", Metadata{IP: ip("9.9.9.9"), Source: ip("10.20.0.5")}, "set"},
		{"src port", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 61001}, "set"},
		{"src port miss", Metadata{IP: ip("9.9.9.9"), Source: src, SrcPort: 61002}, ""},
		{"in port", Metadata{IP: ip("9.9.9.9"), Source: src, InPort: 7000}, "set"},
		{"in name", Metadata{IP: ip("9.9.9.9"), Source: src, InName: "lab"}, "set"},
		{"in type", Metadata{IP: ip("9.9.9.9"), Source: src, InType: "shadowsocks"}, "set"},
		{"protocol", Metadata{IP: ip("9.9.9.9"), Source: src, Protocol: "http"}, "set"},
		{"dst port list", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 9100}, "set"},
		{"dst port miss", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 9002}, ""},
		{"and not hit", Metadata{Host: "a.and.example", Source: src, Port: 443}, "set"},
		{"and not miss", Metadata{Host: "a.and.example", Source: src, Port: 80}, ""},
		{"or 1", Metadata{Host: "o1.example", Source: src}, "set"},
		{"or nested and", Metadata{Host: "o2.example", Source: src, Network: "udp"}, "set"},
		{"or nested and miss", Metadata{Host: "o2.example", Source: src, Network: "tcp"}, ""},
	})
	// GEOSITE / IP-ASN in a rule set without the database block are refused.
	_, err := parseRuleSetAs("classical", "", []byte("GEOSITE,google\n"), maxSetEntries, parseEnv{})
	if dataClass(err) != classUnsup {
		t.Fatal(err)
	}
	_, err = parseRuleSetAs("classical", "", []byte("IP-ASN,1\n"), maxSetEntries, parseEnv{})
	if dataClass(err) != classUnsup {
		t.Fatal(err)
	}
	// Unsupported inside a logical rule names the line.
	_, err = parseRuleSetAs("classical", "", []byte("DOMAIN,a.example\nOR,((DOMAIN,b),(USER-AGENT,x))\n"), maxSetEntries, parseEnv{})
	if dataClass(err) != classUnsup || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "USER-AGENT") {
		t.Fatal(err)
	}
}

func TestGeositeDecoder(t *testing.T) {
	db, err := parseGeositeDB(testGeosite())
	if err != nil {
		t.Fatal(err)
	}
	if len(db.index) != 2 {
		t.Fatal(db.index)
	}
	if !db.matcher("empty").dom.empty() || db.matcher("empty").missing {
		t.Fatal("empty category")
	}
	if !db.matcher("nope").missing {
		t.Fatal("missing category")
	}
	if !db.matcher("google@ads").dom.match("full.google.example") || db.matcher("google@ads").dom.match("google.com") {
		t.Fatal("@ads")
	}
	if !db.matcher("google@cn@!ads").dom.match("google.cn") {
		t.Fatal("@cn@!ads")
	}
	for _, bad := range [][]byte{nil, {0xff}, {0x0a, 0x05, 0x0a}, []byte("<html>")} {
		if _, err := parseGeositeDB(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// Truncation anywhere is rejected or yields a usable prefix, never a panic.
	b := testGeosite()
	for i := range b {
		db, err := parseGeositeDB(b[:i])
		if err == nil {
			db.matcher("google").dom.match("google.com")
		}
	}
}

func TestASNDatabaseFailureKeepsOld(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "asn.mmdb")
	os.WriteFile(p, []byte("not a database"), 0o644)
	ev := &eventLog{}
	e := mustEngine(t, Options{
		Rules: []Rule{{IPASN: "13335", Outbound: "cf", NoResolve: true}},
		ASN:   &GeoIPOptions{Path: p},
	}, ev)
	if ev.count("asn_update_failed", "class", "parse") != 1 {
		t.Fatal(ev.all())
	}
	if d := decideIP(t, e, "1.1.1.1", 443); d.Kind != Direct {
		t.Fatal("no database: ASN rules never match", d)
	}
}

func TestCheckFilesReportsUnsupported(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.list")
	os.WriteFile(good, []byte("DOMAIN,a.example\n"), 0o644)
	bad := filepath.Join(dir, "bad.list")
	os.WriteFile(bad, []byte("DOMAIN,a.example\nPROCESS-NAME,curl\n"), 0o644)
	o := Options{RuleSets: []RuleSetOptions{
		{Name: "good", Format: "surge-ruleset", Path: good},
		{Name: "bad", Format: "classical", Path: bad},
		{Name: "later", Format: "domain", Path: filepath.Join(dir, "missing"), URL: "https://example.invalid/x"},
	}}
	err := CheckFiles(o)
	if err == nil || !strings.Contains(err.Error(), "rule_set bad: unsupported (line 2: rule type PROCESS-NAME)") || strings.Contains(err.Error(), "good") || strings.Contains(err.Error(), "later") {
		t.Fatal(err)
	}
	o.RuleSets = o.RuleSets[:1]
	if err := CheckFiles(o); err != nil {
		t.Fatal(err)
	}
}
