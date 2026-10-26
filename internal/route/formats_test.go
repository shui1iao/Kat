package route

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The testdata fixtures were produced by the reference tools:
//   sb-v1/v2.srs  sing-box 1.14.3 "rule-set compile" of sb-v1/v2.json
//   sb-unsup.srs  the same for a rule set with process_name
//   mrs-*.mrs     mihomo v1.19.33 "convert-ruleset <behavior> text"

func fixture(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func setEngine(t *testing.T, so RuleSetOptions) (*Engine, *eventLog) {
	t.Helper()
	so.Name = "s"
	ev := &eventLog{}
	e := mustEngine(t, Options{Rules: []Rule{{RuleSet: "s", Outbound: "hit"}}, RuleSets: []RuleSetOptions{so}}, ev)
	if ev.count("rule_set_loaded", "name", "s") != 1 {
		t.Fatalf("%+v: %v", so, ev.all())
	}
	return e, ev
}

func TestSingBoxFormats(t *testing.T) {
	src := ip("198.51.100.200")
	cases := []extCase{
		{"exact", Metadata{Host: "exact.example", Source: src}, "hit"},
		{"exact sub", Metadata{Host: "a.exact.example", Source: src}, ""},
		{"suffix apex", Metadata{Host: "suffix.example", Source: src}, "hit"},
		{"suffix sub", Metadata{Host: "a.b.suffix.example", Source: src}, "hit"},
		{"suffix not label", Metadata{Host: "xsuffix.example", Source: src}, ""},
		{"dot suffix apex", Metadata{Host: "dot.example", Source: src}, ""},
		{"dot suffix sub", Metadata{Host: "x.dot.example", Source: src}, "hit"},
		{"keyword", Metadata{Host: "akw-testb.example", Source: src}, "hit"},
		{"regex", Metadata{Host: "re12.example", Source: src}, "hit"},
		{"regex miss", Metadata{Host: "rex.example", Source: src}, ""},
		{"cidr4", Metadata{IP: ip("203.0.113.5"), Source: src}, "hit"},
		{"cidr6", Metadata{IP: ip("2001:db8:1::5"), Source: src}, "hit"},
		{"cidr miss", Metadata{IP: ip("203.0.114.5"), Source: src}, ""},
		{"port udp", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 8443, Network: "udp"}, "hit"},
		{"port tcp", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 8443, Network: "tcp"}, ""},
		{"range lo", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 9000, Network: "udp"}, "hit"},
		{"range hi", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 9010, Network: "udp"}, "hit"},
		{"range out", Metadata{IP: ip("9.9.9.9"), Source: src, Port: 9011, Network: "udp"}, ""},
		{"logical and-not", Metadata{Host: "x.logic.example", Source: src, Port: 80}, "hit"},
		{"logical and-not 443", Metadata{Host: "x.logic.example", Source: src, Port: 443}, ""},
		{"source and domain", Metadata{Host: "src.example", Source: ip("192.0.2.9")}, "hit"},
		{"source mismatch", Metadata{Host: "src.example", Source: src}, ""},
	}
	for _, f := range []RuleSetOptions{
		{Format: "sing-box-json", Path: fixture(t, "sb-v1.json")},
		{Format: "sing-box-json", Path: fixture(t, "sb-v2.json")},
		{Format: "srs", Path: fixture(t, "sb-v1.srs")},
		{Format: "srs", Path: fixture(t, "sb-v2.srs")},
	} {
		e, _ := setEngine(t, f)
		t.Run(filepath.Base(f.Path), func(t *testing.T) { runCases(t, e, nil, cases) })
	}
	for _, f := range []string{"sb-unsup.json", "sb-unsup.srs"} {
		format := "srs"
		if strings.HasSuffix(f, ".json") {
			format = "sing-box-json"
		}
		b, _ := os.ReadFile(fixture(t, f))
		_, err := parseRuleSetAs(format, "", b, maxSetEntries, parseEnv{})
		if dataClass(err) != classUnsup || !strings.Contains(err.Error(), "process_name") {
			t.Fatal(f, err)
		}
	}
	// JSON details: unknown keys, bad versions, rule actions are refused.
	for _, s := range []string{
		`{"version":2,"rules":[{"domain":["a.example"],"outbound":"x"}]}`,
		`{"version":9,"rules":[]}`,
		`{"version":2,"rules":[{"wifi_ssid":["home"]}]}`,
		`{"version":2,"rules":[{"type":"logical","mode":"xor","rules":[{"domain":["a"]},{"domain":["b"]}]}]}`,
	} {
		_, err := parseRuleSetAs("sing-box-json", "", []byte(s), maxSetEntries, parseEnv{})
		if err == nil {
			t.Fatal("accepted", s)
		}
	}
	// Truncated or corrupt srs never panics.
	b, _ := os.ReadFile(fixture(t, "sb-v2.srs"))
	for i := 0; i < len(b); i++ {
		parseRuleSetAs("srs", "", b[:i], maxSetEntries, parseEnv{})
		c := append([]byte(nil), b...)
		c[i] ^= 0x5a
		parseRuleSetAs("srs", "", c, maxSetEntries, parseEnv{})
	}
}

func TestMRS(t *testing.T) {
	e, _ := setEngine(t, RuleSetOptions{Format: "mrs", Behavior: "domain", Path: fixture(t, "mrs-domain.mrs")})
	runCases(t, e, nil, []extCase{
		{"+. apex", Metadata{Host: "plus.example"}, "hit"},
		{"+. sub", Metadata{Host: "a.b.plus.example"}, "hit"},
		{"exact", Metadata{Host: "exact.example"}, "hit"},
		{"exact sub", Metadata{Host: "x.exact.example"}, ""},
		{". apex", Metadata{Host: "dot.example"}, ""},
		{". sub", Metadata{Host: "a.b.dot.example"}, "hit"},
		{"*. one label", Metadata{Host: "a.star.example"}, "hit"},
		{"*. apex", Metadata{Host: "star.example"}, ""},
		{"*. two labels", Metadata{Host: "a.b.star.example"}, ""},
	})
	e, _ = setEngine(t, RuleSetOptions{Format: "mrs", Behavior: "ipcidr", Path: fixture(t, "mrs-ip.mrs")})
	runCases(t, e, nil, []extCase{
		{"v4", Metadata{IP: ip("203.0.113.255")}, "hit"},
		{"v4 /32", Metadata{IP: ip("198.51.100.7")}, "hit"},
		{"v4 /32 miss", Metadata{IP: ip("198.51.100.8")}, ""},
		{"v6", Metadata{IP: ip("2001:db8:1:ffff::1")}, "hit"},
		{"v6 miss", Metadata{IP: ip("2001:db8:2::1")}, ""},
	})
	// Behavior mismatch and corrupt content are rejected.
	b, _ := os.ReadFile(fixture(t, "mrs-domain.mrs"))
	if _, err := parseRuleSetAs("mrs", "ipcidr", b, maxSetEntries, parseEnv{}); err == nil {
		t.Fatal("behavior mismatch accepted")
	}
	for i := 0; i < len(b); i++ {
		parseRuleSetAs("mrs", "domain", b[:i], maxSetEntries, parseEnv{})
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestYAMLAndSurgeFormats(t *testing.T) {
	src := ip("192.0.2.1")
	yamlDomain := "# comment\npayload:\n  - '+.plus.example'\n  - \"exact.example\"\n  - '.dot.example'\n  - 'kw.*.example'\n"
	e, _ := setEngine(t, RuleSetOptions{Format: "yaml", Behavior: "domain", Path: writeFile(t, "d.yaml", yamlDomain)})
	runCases(t, e, nil, []extCase{
		{"plus", Metadata{Host: "plus.example", Source: src}, "hit"},
		{"exact", Metadata{Host: "exact.example", Source: src}, "hit"},
		{"dot apex", Metadata{Host: "dot.example", Source: src}, ""},
		{"dot sub", Metadata{Host: "x.dot.example", Source: src}, "hit"},
		{"inner wildcard", Metadata{Host: "kw.abc.example", Source: src}, "hit"},
	})
	yamlIP := "payload:\n  - 203.0.113.0/24\n  - '2001:db8::/32'\n"
	e, _ = setEngine(t, RuleSetOptions{Format: "yaml", Behavior: "ipcidr", Path: writeFile(t, "i.yaml", yamlIP)})
	runCases(t, e, nil, []extCase{
		{"v4", Metadata{IP: ip("203.0.113.9"), Source: src}, "hit"},
		{"v6", Metadata{IP: ip("2001:db8::9"), Source: src}, "hit"},
		{"miss", Metadata{IP: ip("192.0.2.9"), Source: src}, ""},
	})
	yamlClassical := "payload:\n  - DOMAIN-SUFFIX,c.example\n  - IP-CIDR,198.51.100.0/24,no-resolve\n  - AND,((NETWORK,udp),(DST-PORT,443))\n"
	e, _ = setEngine(t, RuleSetOptions{Format: "yaml", Behavior: "classical", Path: writeFile(t, "c.yaml", yamlClassical)})
	runCases(t, e, nil, []extCase{
		{"suffix", Metadata{Host: "a.c.example", Source: src}, "hit"},
		{"cidr", Metadata{IP: ip("198.51.100.1"), Source: src}, "hit"},
		{"and", Metadata{IP: ip("9.9.9.9"), Network: "udp", Port: 443, Source: src}, "hit"},
		{"and miss", Metadata{IP: ip("9.9.9.9"), Network: "tcp", Port: 443, Source: src}, ""},
	})
	if _, err := parseRuleSetAs("yaml", "classical", []byte("payload:\n  - PROCESS-NAME,curl\n"), maxSetEntries, parseEnv{}); dataClass(err) != classUnsup {
		t.Fatal(err)
	}
	for _, bad := range []string{"payload: 5\n", "rules:\n  - a\n", "payload:\n  - [a, b]\n", "\tbad: [\n"} {
		if _, err := parseRuleSetAs("yaml", "domain", []byte(bad), maxSetEntries, parseEnv{}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// Surge DOMAIN-SET: ".x" is x and its subdomains, "x" is exact.
	e, _ = setEngine(t, RuleSetOptions{Format: "surge-domain-set", Path: writeFile(t, "ds.txt", "# c\n.both.example\nexact.example\n")})
	runCases(t, e, nil, []extCase{
		{".both apex", Metadata{Host: "both.example", Source: src}, "hit"},
		{".both sub", Metadata{Host: "a.both.example", Source: src}, "hit"},
		{"exact", Metadata{Host: "exact.example", Source: src}, "hit"},
		{"exact sub", Metadata{Host: "a.exact.example", Source: src}, ""},
	})
	// Surge RULE-SET (classical): Surge type names and options.
	surge := "DOMAIN-SUFFIX,s.example\nDEST-PORT,8443\nSRC-IP,192.0.2.0/24\nIP-CIDR,203.0.113.0/24,no-resolve\n"
	e, _ = setEngine(t, RuleSetOptions{Format: "surge-ruleset", Path: writeFile(t, "s.list", surge)})
	runCases(t, e, nil, []extCase{
		{"suffix", Metadata{Host: "s.example", Source: ip("198.51.100.1")}, "hit"},
		{"dest port", Metadata{IP: ip("9.9.9.9"), Port: 8443, Source: ip("198.51.100.1")}, "hit"},
		{"src ip", Metadata{IP: ip("9.9.9.9"), Source: ip("192.0.2.77")}, "hit"},
		{"miss", Metadata{IP: ip("9.9.9.9"), Source: ip("198.51.100.1")}, ""},
	})
	for _, l := range []string{"USER-AGENT,curl*", "URL-REGEX,^http://", "PROCESS-NAME,curl", "DOMAIN-SET,https://x", "RULE-SET,https://x", "DOMAIN,a.example,extended-matching"} {
		if _, err := parseRuleSetAs("surge-ruleset", "", []byte(l+"\n"), maxSetEntries, parseEnv{}); dataClass(err) != classUnsup {
			t.Fatal(l, err)
		}
	}
}

// Unknown rule-provider fields and structured payload entries must fail the
// whole set, including when valid rules precede the unsupported content.
func TestYAMLRejectsUnsupportedFields(t *testing.T) {
	for _, input := range []string{
		"payload:\n  - good.example\nunsupported-option: true\n",
		"payload:\n  - good.example\n  - {domain: hidden.example}\n",
		"payload:\n  - good.example\n  - [hidden.example]\n",
	} {
		_, err := parseRuleSetAs("yaml", "domain", []byte(input), maxSetEntries, parseEnv{})
		if dataClass(err) != classUnsup {
			t.Fatalf("accepted or misclassified %q: %v", input, err)
		}
	}
	if _, err := parseRuleSetAs("yaml", "domain", []byte("payload: [good.example]\n---\npayload: [hidden.example]\n"), maxSetEntries, parseEnv{}); err == nil {
		t.Fatal("silently discarded second YAML document")
	}
}
