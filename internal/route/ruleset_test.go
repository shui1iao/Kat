package route

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const domainSample = "# Surge DOMAIN-SET / mihomo domain text\r\n" +
	".apple.com\r\n" +
	"+.google.com\n" +
	"exact.example\n" +
	"  Upper.Example.ORG.  \n" +
	"// comment\n" +
	"; comment\n" +
	"\n" +
	"*.wild.example\n" +
	"bad..domain\n" +
	"under_score.example\n" +
	"crlf.example\r\n"

const ipcidrSample = "# comment\n1.0.1.0/24\n2001:da8::/32\n8.8.8.8\n::ffff:9.9.9.0/120\n999.1.1.1/8\nnot-an-ip\n2001:db8::1\n"

const classicalSample = `# Surge RULE-SET / mihomo classical text
DOMAIN,exact.example
DOMAIN-SUFFIX,suffix.example
DOMAIN-KEYWORD,tracker
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR6,2001:db8:abcd::/48
IP-CIDR,198.51.100.0/24
GEOIP,CN
DST-PORT,6881-6889
AND,((DOMAIN,a.example),(DST-PORT,443))
IP-CIDR,300.0.0.0/8
garbage line
 domain-suffix , lower.example
`

func TestParseDomainSet(t *testing.T) {
	d, err := parseRuleSet("domain", []byte("\xef\xbb\xbf"+domainSample), maxSetEntries)
	if err != nil {
		t.Fatal(err)
	}
	if d.entries != 6 || d.skipped != 2 {
		t.Fatalf("entries=%d skipped=%d", d.entries, d.skipped)
	}
	// 0.7.0: "*.x" is mihomo's one-label wildcard (0.6 skipped it).
	yes := []string{"apple.com", "www.apple.com", "google.com", "a.b.google.com", "exact.example", "upper.example.org", "crlf.example", "x.wild.example"}
	no := []string{"notapple.com", "com", "sub.exact.example", "wild.example", "a.x.wild.example", "example.org", "bad..domain", ""}
	for _, h := range yes {
		if !d.dom.match(h) {
			t.Fatal("should match", h)
		}
	}
	for _, h := range no {
		if d.dom.match(h) {
			t.Fatal("should not match", h)
		}
	}
	if !d.ip.empty() || len(d.geo) != 0 {
		t.Fatal("domain set has IP entries")
	}
}

func TestParseIPCIDRSet(t *testing.T) {
	d, err := parseRuleSet("ipcidr", []byte(ipcidrSample), maxSetEntries)
	if err != nil {
		t.Fatal(err)
	}
	if d.entries != 5 || d.skipped != 2 {
		t.Fatalf("entries=%d skipped=%d", d.entries, d.skipped)
	}
	for _, s := range []string{"1.0.1.77", "2001:da8:1::1", "8.8.8.8", "9.9.9.5", "2001:db8::1"} {
		if !d.ip.contains(netip.MustParseAddr(s)) {
			t.Fatal("should contain", s)
		}
	}
	for _, s := range []string{"1.0.2.1", "8.8.8.9", "9.9.8.1", "2001:db8::2", "::ffff:1.0.1.1"} {
		if d.ip.contains(netip.MustParseAddr(s)) {
			t.Fatal("should not contain (raw, unmapped by Decide)", s)
		}
	}
}

func TestParseClassicalSet(t *testing.T) {
	d, err := parseRuleSet("classical", []byte(classicalSample), maxSetEntries)
	if err != nil {
		t.Fatal(err)
	}
	if d.entries != 10 || d.skipped != 2 {
		t.Fatalf("entries=%d skipped=%d", d.entries, d.skipped)
	}
	// Unsupported rule types and options refuse the whole set (0.6 skipped them).
	for _, l := range []string{"PROCESS-NAME,foo.exe", "USER-AGENT,Foo*", "URL-REGEX,^http://x", "IP-ASN,13335,no-resolve", "DOMAIN-SUFFIX,policy.example,DIRECT", "SUB-RULE,(NETWORK,tcp),sub", "RULE-SET,x", "MATCH", "AND,((DOMAIN,a),(PROCESS-NAME,b))"} {
		_, err := parseRuleSet("classical", []byte("DOMAIN,ok.example\n"+l+"\n"), maxSetEntries)
		var u *unsupportedError
		if !errors.As(err, &u) || !strings.Contains(err.Error(), "line 2") {
			t.Fatal(l, err)
		}
	}
	for _, h := range []string{"exact.example", "suffix.example", "a.suffix.example", "my-tracker.test", "lower.example"} {
		if !d.dom.match(h) {
			t.Fatal("domain", h)
		}
	}
	if d.dom.match("a.exact.example") || d.dom.match("policy.example") || d.dom.match("a.example") {
		t.Fatal("unexpected domain match")
	}
	if !d.ipNR.contains(netip.MustParseAddr("203.0.113.5")) || d.ip.contains(netip.MustParseAddr("203.0.113.5")) {
		t.Fatal("no-resolve entry placement")
	}
	if !d.ip.contains(netip.MustParseAddr("2001:db8:abcd::9")) || !d.ip.contains(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("ip entries")
	}
	if !slices.Equal(d.geo, []string{"CN"}) || !portIn(d.ports, 6885) || portIn(d.ports, 6890) {
		t.Fatal("geo/port", d.geo, d.ports)
	}
}

func TestParseFailures(t *testing.T) {
	html := []byte("<!DOCTYPE html>\n<html><body>404 Not Found</body></html>\n")
	for _, f := range []string{"domain", "ipcidr", "classical"} {
		if _, err := parseRuleSet(f, html, maxSetEntries); !errors.Is(err, errParse) {
			t.Fatal(f, "html accepted", err)
		}
		if _, err := parseRuleSet(f, []byte("a.example\x00\x01"), maxSetEntries); !errors.Is(err, errParse) {
			t.Fatal(f, "binary accepted", err)
		}
		if _, err := parseRuleSet(f, []byte{0xff, 0xfe, 'a'}, maxSetEntries); !errors.Is(err, errParse) {
			t.Fatal(f, "invalid utf-8 accepted", err)
		}
		d, err := parseRuleSet(f, []byte("# only comments\n\n"), maxSetEntries)
		if err != nil || d.entries != 0 {
			t.Fatal(f, "empty set", err)
		}
	}
	if _, err := parseRuleSet("domain", []byte("a.x\nb.x\nc.x\nd.x\ne.x\n"), 4); !errors.Is(err, errLimit) {
		t.Fatal("per-set limit", err)
	}
	if d, err := parseRuleSet("domain", []byte("a.x\nb.x\nc.x\nd.x\n"), 4); err != nil || d.entries != 4 {
		t.Fatal("at limit", err)
	}
	// Unsupported lines are an error, not an empty set.
	if _, err := parseRuleSet("classical", []byte("PROCESS-NAME,a\nUSER-AGENT,b\n"), maxSetEntries); dataClass(err) != classUnsup {
		t.Fatal("unsupported-only", err)
	}
}

func TestRuleSetEngineEventsAndLimits(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ev := &eventLog{}
	o := Options{
		Rules: []Rule{{RuleSet: "c", Outbound: "C"}, {RuleSet: "d", Outbound: "D"}, {RuleSet: "i", Outbound: "I"}, {RuleSet: "bad", Outbound: "B"}, {RuleSet: "gone", Outbound: "G"}, {RuleSet: "big", Outbound: "X"}},
		RuleSets: []RuleSetOptions{
			{Name: "c", Format: "classical", Path: write("c.txt", classicalSample)},
			{Name: "d", Format: "domain", Path: write("d.txt", domainSample)},
			{Name: "i", Format: "ipcidr", Path: write("i.txt", ipcidrSample)},
			{Name: "bad", Format: "ipcidr", Path: write("bad.txt", "<html>\n")},
			{Name: "gone", Format: "domain", Path: filepath.Join(dir, "missing.txt")},
			{Name: "big", Format: "domain", Path: write("big.txt", strings.Repeat("a.example\n", 2000)), MaxBytes: 1024},
		},
	}
	e := mustEngine(t, o, ev)
	if ev.count("rule_set_loaded", "name", "c", "entries", "10", "skipped", "2") != 1 ||
		ev.count("rule_set_loaded", "name", "d", "entries", "6", "skipped", "2") != 1 ||
		ev.count("rule_set_loaded", "name", "i", "entries", "5", "skipped", "2") != 1 ||
		ev.count("rule_set_update_failed", "name", "bad", "class", "parse") != 1 ||
		ev.count("rule_set_update_failed", "name", "gone", "class", "missing") != 1 ||
		ev.count("rule_set_update_failed", "name", "big", "class", "too_large") != 1 {
		t.Fatal("events", ev.all())
	}
	if d, _ := decideHost(t, e, "www.apple.com", 80, &fakeDNS{}); d.Outbound != "D" {
		t.Fatal(d)
	}
	if d := decideIP(t, e, "1.0.1.1", 80); d.Outbound != "I" {
		t.Fatal(d)
	}
	if d := decideIP(t, e, "203.0.113.1", 80); d.Outbound != "C" {
		t.Fatal(d)
	}
	// Failed sets are empty: never match, never trigger DNS on their own.
	if d, _ := decideHost(t, e, "a.example", 80, &fakeDNS{ips: addrs("1.0.1.1")}); d.Outbound != "I" {
		t.Fatal(d)
	}
	// Total entry limit across sets.
	defer func(v int) { totalEntryLimit = v }(totalEntryLimit)
	totalEntryLimit = 12
	ev2 := &eventLog{}
	mustEngine(t, Options{RuleSets: []RuleSetOptions{
		{Name: "c", Format: "classical", Path: filepath.Join(dir, "c.txt")},
		{Name: "d", Format: "domain", Path: filepath.Join(dir, "d.txt")},
	}}, ev2)
	if ev2.count("rule_set_loaded", "name", "c") != 1 || ev2.count("rule_set_update_failed", "name", "d", "class", "limit") != 1 {
		t.Fatal("total limit", ev2.all())
	}
	for _, x := range ev.all() {
		for _, f := range x {
			if strings.Contains(f, "/") || strings.Contains(f, "example") {
				t.Fatal("event leaks path/target", x)
			}
		}
	}
}

// TestLargeDomainSetLoad records load time and heap for a 1,000,000-entry
// domain set. Opt-in (memory heavy): KAT_ROUTE_BIG=1.
func TestLargeDomainSetLoad(t *testing.T) {
	if os.Getenv("KAT_ROUTE_BIG") != "1" {
		t.Skip("set KAT_ROUTE_BIG=1")
	}
	var b strings.Builder
	for i := 0; i < maxSetEntries; i++ {
		if i%4 == 0 {
			b.WriteString("+.")
		}
		b.WriteString("host-")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(".example-")
		b.WriteString(strconv.Itoa(i % 997))
		b.WriteString(".com\n")
	}
	p := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	size := b.Len()
	b = strings.Builder{}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	ev := &eventLog{}
	start := time.Now()
	e, err := NewEngine(Options{Rules: []Rule{{RuleSet: "big", Action: "reject"}}, RuleSets: []RuleSetOptions{{Name: "big", Format: "domain", Path: p, MaxBytes: 64 << 20}}}, nil, ev.sink)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if ev.count("rule_set_loaded", "name", "big", "entries", strconv.Itoa(maxSetEntries), "skipped", "0") != 1 {
		t.Fatal(ev.all())
	}
	q0 := time.Now()
	const lookups = 100000
	hits := 0
	for i := 0; i < lookups; i++ {
		d, _ := decideHost(t, e, "x.host-"+strconv.Itoa(i*8)+".example-"+strconv.Itoa(i*8%997)+".com", 443, &fakeDNS{ips: addrs("192.0.2.1")})
		if d.Kind == Reject {
			hits++
		}
	}
	per := time.Since(q0) / lookups
	if hits != lookups { // i*8 is a multiple of 4: always a suffix entry
		t.Fatal("hits", hits)
	}
	t.Logf("1,000,000-entry domain set: file %d bytes, load %v, retained heap %.1f MiB (HeapAlloc %d -> %d), Decide suffix hit %v/op",
		size, elapsed, float64(int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/(1<<20), m0.HeapAlloc, m1.HeapAlloc, per)
	runtime.KeepAlive(e)
}
