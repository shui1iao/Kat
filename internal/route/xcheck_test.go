package route

// Cross-checks against real public rule data and the reference tools. Skipped
// unless KAT_RULES_XCHECK names the data directory; the tools come from
// KAT_INTEROP_SINGBOX (sing-box, "rule-set match/decompile") and
// KAT_INTEROP_MIHOMO (mihomo, "convert-ruleset"). KAT_RULES_XCHECK_N sets
// the samples per file (default 3000).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

func xcheckEnv(t *testing.T) (dir string, n int) {
	dir = os.Getenv("KAT_RULES_XCHECK")
	if dir == "" {
		t.Skip("KAT_RULES_XCHECK not set")
	}
	n = 3000
	if v, err := strconv.Atoi(os.Getenv("KAT_RULES_XCHECK_N")); err == nil && v > 0 {
		n = v
	}
	return dir, n
}

func heapLive() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

type loaded struct {
	e *Engine
	d *setData
}

func loadSet(t *testing.T, path, format, behavior string, o Options) (loaded, error) {
	t.Helper()
	o.Rules = []Rule{{RuleSet: "x", Outbound: "hit"}}
	o.RuleSets = []RuleSetOptions{{Name: "x", Format: format, Behavior: behavior, Path: path, MaxBytes: maxSetBytes}}
	ev := &eventLog{}
	e, err := NewEngine(o, nil, ev.sink)
	if err != nil {
		return loaded{}, err
	}
	if ev.count("rule_set_loaded", "name", "x") != 1 {
		e.Close()
		return loaded{}, fmt.Errorf("%v", ev.all())
	}
	return loaded{e, e.sets[0].data.Load()}, nil
}

func (l loaded) matchHost(h string) bool { return l.d.match(l.e, &query{host: h}, nil) }
func (l loaded) matchIP(a netip.Addr) bool {
	return l.d.match(l.e, &query{}, &ipInfo{ip: a})
}

// ---- 1. every public file loads; size, time, memory and match cost ----

func TestXCheckLoadRealSets(t *testing.T) {
	dir, _ := xcheckEnv(t)
	asn := &GeoIPOptions{Path: filepath.Join(dir, "GeoLite2-ASN.mmdb")}
	files := []struct{ file, format, behavior string }{
		{"clash-google.yaml", "yaml", "classical"},
		{"clash-china.yaml", "yaml", "classical"},
		{"clash-chinamax-classical.yaml", "yaml", "classical"},
		{"clash-chinamax-domain.txt", "domain", ""},
		{"clash-chinamax-ip.txt", "ipcidr", ""},
		{"loyal-direct.yaml", "yaml", "domain"},
		{"loyal-reject.yaml", "yaml", "domain"},
		{"loyal-cncidr.yaml", "yaml", "ipcidr"},
		{"loyal-applications.yaml", "yaml", "classical"},
		{"mrs-geosite-cn.mrs", "mrs", "domain"},
		{"mrs-geosite-google.mrs", "mrs", "domain"},
		{"mrs-geosite-category-ads-all.mrs", "mrs", "domain"},
		{"mrs-geoip-cn.mrs", "mrs", "ipcidr"},
		{"srs-geosite-cn.srs", "srs", ""},
		{"srs-geosite-google.srs", "srs", ""},
		{"srs-geoip-cn.srs", "srs", ""},
		{"sagernet-geosite-cn.srs", "srs", ""},
		{"sagernet-geosite-netflix.srs", "srs", ""},
		{"singjson-geosite-google.json", "sing-box-json", ""},
		{"singjson-geoip-cn.json", "sing-box-json", ""},
		{"surge-google.list", "surge-ruleset", ""},
		{"surge-china.list", "surge-ruleset", ""},
		{"surge-skk-cdn-ruleset.conf", "surge-ruleset", ""},
		{"surge-loyal-direct-domainset.txt", "surge-domain-set", ""},
		{"surge-loyal-reject-domainset.txt", "surge-domain-set", ""},
		{"surge-skk-reject-domainset.conf", "surge-domain-set", ""},
	}
	// Lists with rule types Kat does not support (PROCESS-NAME...) are
	// refused as a whole with the line named; with those lines removed
	// (a ".kat" copy) they load.
	unsupportedRE := regexp.MustCompile(`(?m)^.*(PROCESS-NAME|PROCESS-PATH|USER-AGENT|URL-REGEX)[^\n]*\n?`)
	for i, f := range files {
		p := filepath.Join(dir, f.file)
		_, err := loadSet(t, p, f.format, f.behavior, Options{ASN: asn})
		if err == nil {
			continue
		}
		if !strings.Contains(err.Error(), "class unsupported") {
			t.Fatalf("%s: %v", f.file, err)
		}
		t.Logf("%s (original): refused: %v", f.file, err)
		raw, _ := os.ReadFile(p)
		stripped := unsupportedRE.ReplaceAll(raw, nil)
		if !regexp.MustCompile(`(?m)^\s*-?\s*[A-Z]`).Match(stripped) {
			t.Logf("%s: only unsupported rules, nothing left to load", f.file)
			files[i].file = ""
			continue
		}
		files[i].file = f.file + ".kat"
		os.WriteFile(p+".kat", stripped, 0o644)
	}
	// The ASN database (used by IP-ASN lines) stays loaded outside the
	// measurements: parsed data is shared between engines.
	holder := mustEngine(t, Options{ASN: asn}, nil)
	defer runtime.KeepAlive(holder)
	rng := rand.New(rand.NewSource(1))
	hosts := make([]string, 20000)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example%d.com", rng.Intn(1e6), i%97)
	}
	t.Logf("%-42s %-15s %8s %8s %10s %10s %12s", "file", "format", "entries", "skipped", "load", "heap", "match/op")
	for _, f := range files {
		if f.file == "" {
			continue
		}
		p := filepath.Join(dir, f.file)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		o := Options{}
		if f.behavior == "classical" || f.format == "surge-ruleset" {
			o.ASN = asn // IP-ASN lines need the block (its file read is included)
		}
		before := heapLive()
		start := time.Now()
		l, err := loadSet(t, p, f.format, f.behavior, o)
		took := time.Since(start)
		if err != nil {
			t.Fatalf("%s: %v", f.file, err)
		}
		heap := int64(heapLive()) - int64(before)
		var matchNS float64
		if f.behavior == "ipcidr" || strings.Contains(f.file, "geoip") || strings.Contains(f.file, "-ip") {
			ips := make([]netip.Addr, len(hosts))
			for i := range ips {
				ips[i] = netip.AddrFrom4([4]byte{byte(rng.Intn(224)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
			}
			s := time.Now()
			for _, a := range ips {
				l.matchIP(a)
			}
			matchNS = float64(time.Since(s).Nanoseconds()) / float64(len(ips))
		} else {
			s := time.Now()
			for _, h := range hosts {
				l.matchHost(h)
			}
			matchNS = float64(time.Since(s).Nanoseconds()) / float64(len(hosts))
		}
		t.Logf("%-42s %-15s %8d %8d %10s %8.1fMB %10.0fns  (%d bytes)", f.file, f.format, l.d.entries, l.d.skipped, took.Round(time.Millisecond), float64(heap)/(1<<20), matchNS, fi.Size())
		runtime.KeepAlive(l)
		l.e.Close()
	}
}

// ---- 2. srs: Kat vs "sing-box rule-set match" ----

type sbSource struct {
	Version int `json:"version"`
	Rules   []map[string]json.RawMessage
}

func strList(raw json.RawMessage) []string {
	var l []string
	if json.Unmarshal(raw, &l) == nil {
		return l
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	return nil
}

func domainSamples(rng *rand.Rand, exact, suffix, keyword []string, n int) []string {
	var out []string
	add := func(s string) {
		if s != "" && len(out) < n {
			out = append(out, strings.ToLower(s))
		}
	}
	pick := func(l []string) string {
		if len(l) == 0 {
			return ""
		}
		return strings.TrimPrefix(l[rng.Intn(len(l))], ".")
	}
	for len(out) < n {
		switch rng.Intn(10) {
		case 0, 1:
			add(pick(exact))
		case 2:
			add("a" + strconv.Itoa(rng.Intn(9)) + "." + pick(exact))
		case 3, 4:
			add(pick(suffix))
		case 5:
			add("x." + pick(suffix))
		case 6:
			s := pick(suffix)
			if i := strings.IndexByte(s, '.'); i > 0 {
				add(s[i+1:]) // parent
			}
		case 7:
			add("z" + pick(append(append([]string{}, exact...), suffix...))) // not a label boundary
		case 8:
			if k := pick(keyword); k != "" {
				add("p" + k + "q.example")
			} else {
				add(fmt.Sprintf("r%d.example.org", rng.Intn(1e6)))
			}
		default:
			add(fmt.Sprintf("n%d.example%d.net", rng.Intn(1e6), rng.Intn(50)))
		}
	}
	return out
}

func ipSamples(rng *rand.Rand, cidrs []string, n int) []string {
	var out []string
	for len(out) < n {
		if len(cidrs) == 0 || rng.Intn(5) == 0 {
			out = append(out, netip.AddrFrom4([4]byte{byte(1 + rng.Intn(222)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}).String())
			continue
		}
		p, err := netip.ParsePrefix(cidrs[rng.Intn(len(cidrs))])
		if err != nil {
			continue
		}
		p = p.Masked()
		first := p.Addr()
		last := lastAddr(p)
		switch rng.Intn(4) {
		case 0:
			out = append(out, first.String())
		case 1:
			out = append(out, last.String())
		case 2:
			if n := last.Next(); n.IsValid() {
				out = append(out, n.String())
			}
		default:
			if pr := first.Prev(); pr.IsValid() {
				out = append(out, pr.String())
			}
		}
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// parallel runs f over items with 8 workers.
func parallel(items []string, f func(string) bool) []bool {
	out := make([]bool, len(items))
	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				out[i] = f(items[i])
			}
		}()
	}
	for i := range items {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return out
}

func TestXCheckSRSAgainstSingBox(t *testing.T) {
	dir, n := xcheckEnv(t)
	sb := os.Getenv("KAT_INTEROP_SINGBOX")
	if sb == "" {
		t.Skip("KAT_INTEROP_SINGBOX not set")
	}
	tmp := t.TempDir()
	for _, f := range []string{"srs-geosite-cn.srs", "srs-geosite-google.srs", "srs-geoip-cn.srs", "sagernet-geosite-cn.srs", "sagernet-geosite-netflix.srs"} {
		p := filepath.Join(dir, f)
		js := filepath.Join(tmp, f+".json")
		if out, err := exec.Command(sb, "rule-set", "decompile", "-o", js, p).CombinedOutput(); err != nil {
			t.Fatal(f, err, string(out))
		}
		var src sbSource
		b, _ := os.ReadFile(js)
		if err := json.Unmarshal(b, &src); err != nil {
			t.Fatal(err)
		}
		var exact, suffix, keyword, cidrs []string
		for _, r := range src.Rules {
			exact = append(exact, strList(r["domain"])...)
			suffix = append(suffix, strList(r["domain_suffix"])...)
			keyword = append(keyword, strList(r["domain_keyword"])...)
			cidrs = append(cidrs, strList(r["ip_cidr"])...)
		}
		rng := rand.New(rand.NewSource(int64(len(f))))
		var samples []string
		if len(cidrs) > 0 {
			samples = ipSamples(rng, cidrs, n)
		} else {
			samples = domainSamples(rng, exact, suffix, keyword, n)
		}
		l, err := loadSet(t, p, "srs", "", Options{})
		if err != nil {
			t.Fatal(f, err)
		}
		lj, err := loadSet(t, js, "sing-box-json", "", Options{})
		if err != nil {
			t.Fatal(f, "decompiled json:", err)
		}
		ref := parallel(samples, func(s string) bool {
			out, err := exec.Command(sb, "rule-set", "match", "-f", "binary", p, s).CombinedOutput()
			if err != nil {
				t.Error(s, err, string(out))
			}
			return strings.Contains(string(out), "match rules")
		})
		mismatch, hits := 0, 0
		for i, s := range samples {
			var kat, katJSON bool
			if a, err := netip.ParseAddr(s); err == nil {
				kat, katJSON = l.matchIP(a), lj.matchIP(a)
			} else {
				kat, katJSON = l.matchHost(s), lj.matchHost(s)
			}
			if ref[i] {
				hits++
			}
			if kat != ref[i] || katJSON != ref[i] {
				mismatch++
				if mismatch <= 10 {
					t.Errorf("%s %q: kat srs=%v json=%v sing-box=%v", f, s, kat, katJSON, ref[i])
				}
			}
		}
		t.Logf("%s (srs v%d): %d samples, %d sing-box matches, %d mismatches; entries=%d", f, src.Version, len(samples), hits, mismatch, l.d.entries)
		l.e.Close()
		lj.e.Close()
	}
}

// ---- 3. mrs: Kat vs mihomo's text conversion ----

// mihomoDomain is an independent matcher for mihomo's domain text
// ("+." itself and subdomains, "." subdomains, "*." one label, else exact).
type mihomoDomain struct{ plus, dot, star, exact map[string]bool }

func newMihomoDomain(lines []string) *mihomoDomain {
	m := &mihomoDomain{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "+."):
			m.plus[l[2:]] = true
		case strings.HasPrefix(l, "."):
			m.dot[l[1:]] = true
		case strings.HasPrefix(l, "*."):
			m.star[l[2:]] = true
		default:
			m.exact[l] = true
		}
	}
	return m
}

func (m *mihomoDomain) match(h string) bool {
	if m.exact[h] || m.plus[h] {
		return true
	}
	labels := strings.Split(h, ".")
	for i := 1; i < len(labels); i++ {
		parent := strings.Join(labels[i:], ".")
		if m.plus[parent] || m.dot[parent] || i == 1 && m.star[parent] {
			return true
		}
	}
	return false
}

func readLines(t *testing.T, p string) []string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestXCheckMRSAgainstMihomo(t *testing.T) {
	dir, n := xcheckEnv(t)
	mh := os.Getenv("KAT_INTEROP_MIHOMO")
	if mh == "" {
		t.Skip("KAT_INTEROP_MIHOMO not set")
	}
	tmp := t.TempDir()
	for _, f := range []struct{ file, behavior string }{
		{"mrs-geosite-cn.mrs", "domain"},
		{"mrs-geosite-google.mrs", "domain"},
		{"mrs-geosite-category-ads-all.mrs", "domain"},
		{"mrs-geoip-cn.mrs", "ipcidr"},
	} {
		p := filepath.Join(dir, f.file)
		txt := filepath.Join(tmp, f.file+".txt")
		if out, err := exec.Command(mh, "convert-ruleset", f.behavior, "mrs", p, txt).CombinedOutput(); err != nil {
			t.Fatal(f.file, err, string(out))
		}
		lines := readLines(t, txt)
		l, err := loadSet(t, p, "mrs", f.behavior, Options{})
		if err != nil {
			t.Fatal(f.file, err)
		}
		rng := rand.New(rand.NewSource(int64(len(f.file))))
		mismatch, hits, total := 0, 0, 0
		if f.behavior == "ipcidr" {
			var prefixes []netip.Prefix
			for _, s := range lines {
				prefixes = append(prefixes, netip.MustParsePrefix(s))
			}
			for _, s := range ipSamples(rng, lines, n) {
				a := netip.MustParseAddr(s)
				ref := false
				for _, p := range prefixes {
					if p.Contains(a) {
						ref = true
						break
					}
				}
				total++
				if ref {
					hits++
				}
				if l.matchIP(a) != ref {
					mismatch++
					t.Errorf("%s %s: kat=%v mihomo text=%v", f.file, s, !ref, ref)
				}
			}
		} else {
			ref := newMihomoDomain(lines)
			var plain []string
			for _, s := range lines {
				plain = append(plain, strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(s, "+."), "*."), "."))
			}
			samples := domainSamples(rng, plain, plain, nil, n)
			// Wildcard entries: one and two labels below.
			for s := range ref.star {
				samples = append(samples, "w."+s, "w.v."+s, s)
			}
			for _, s := range samples {
				r := ref.match(s)
				total++
				if r {
					hits++
				}
				if l.matchHost(s) != r {
					mismatch++
					if mismatch <= 10 {
						t.Errorf("%s %q: kat=%v mihomo text=%v", f.file, s, !r, r)
					}
				}
			}
		}
		t.Logf("%s: %d text entries, %d samples, %d matches, %d mismatches", f.file, len(lines), total, hits, mismatch)
		l.e.Close()
	}
}

// ---- 4. geosite.dat vs the v2fly source lists of the same release ----

type dlcEntry struct {
	typ, value string
	attrs      []string
}

// dlcLoad resolves a category of the domain-list-community data directory
// (include:, include attribute filters, &affiliations).
type dlcData struct {
	dir   string
	cache map[string][]dlcEntry
	affil map[string][]dlcEntry
}

func newDLC(t *testing.T, dir string) *dlcData {
	d := &dlcData{dir: dir, cache: map[string][]dlcEntry{}, affil: map[string][]dlcEntry{}}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		for _, e := range d.parse(t, f.Name()) {
			_ = e
		}
	}
	return d
}

func (d *dlcData) parseLine(line string) (dlcEntry, []string, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return dlcEntry{}, nil, false
	}
	e := dlcEntry{typ: "domain", value: fields[0]}
	if k, v, ok := strings.Cut(fields[0], ":"); ok {
		e.typ, e.value = k, v
	}
	var affs []string
	for _, f := range fields[1:] {
		switch {
		case strings.HasPrefix(f, "@"):
			e.attrs = append(e.attrs, strings.ToLower(f[1:]))
		case strings.HasPrefix(f, "&"):
			affs = append(affs, strings.ToLower(f[1:]))
		}
	}
	if e.typ != "regexp" {
		e.value = strings.ToLower(e.value)
	}
	return e, affs, true
}

func (d *dlcData) parse(t *testing.T, name string) []dlcEntry {
	b, err := os.ReadFile(filepath.Join(d.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var out []dlcEntry
	for _, line := range strings.Split(string(b), "\n") {
		e, affs, ok := d.parseLine(line)
		if !ok {
			continue
		}
		out = append(out, e)
		for _, a := range affs {
			d.affil[a] = append(d.affil[a], e)
		}
	}
	return out
}

func (d *dlcData) resolve(t *testing.T, name string, depth int) []dlcEntry {
	if v, ok := d.cache[name]; ok {
		return v
	}
	if depth > 20 {
		t.Fatal("include loop", name)
	}
	var out []dlcEntry
	for _, e := range d.parse(t, name) {
		if e.typ != "include" {
			out = append(out, e)
			continue
		}
		// include:cat @attr @-attr
		parts := strings.Fields(e.value)
		sub := d.resolve(t, parts[0], depth+1)
		for _, s := range sub {
			if attrOK(s.attrs, e.attrs) {
				out = append(out, s)
			}
		}
	}
	out = append(out, d.affil[name]...)
	d.cache[name] = out
	return out
}

// attrOK: filter "x" requires attribute x, "-x" excludes it.
func attrOK(has, filter []string) bool {
	for _, f := range filter {
		neg := strings.HasPrefix(f, "-")
		f = strings.TrimPrefix(f, "-")
		found := false
		for _, h := range has {
			if h == f {
				found = true
			}
		}
		if found == neg {
			return false
		}
	}
	return true
}

// dlcPolish applies the domain-list-community compiler's redundancy trim
// (polishList): a domain entry removes its subdomain entries (domain or full)
// that have no attributes or the same attributes, and "domain:x" removes
// "full:x". geosite.dat holds the trimmed list, so attribute filters see it.
func dlcPolish(entries []dlcEntry) []dlcEntry {
	key := func(e dlcEntry) string {
		a := append([]string(nil), e.attrs...)
		sort.Strings(a)
		return strings.Join(a, ",")
	}
	parents := map[string]bool{}
	for _, e := range entries {
		if e.typ == "domain" {
			parents[e.value+"|"] = true
			parents[e.value+"|"+key(e)] = true
		}
	}
	var out []dlcEntry
	for _, e := range entries {
		if e.typ != "domain" && e.typ != "full" {
			out = append(out, e)
			continue
		}
		pd := e.value
		if e.typ == "full" {
			pd = "." + pd
		}
		redundant := false
		for {
			_, rest, ok := strings.Cut(pd, ".")
			if !ok {
				break
			}
			pd = rest
			if parents[pd+"|"+key(e)] {
				redundant = true
				break
			}
		}
		if !redundant {
			out = append(out, e)
		}
	}
	return out
}

func dlcMatch(entries []dlcEntry, want []string, host string, res map[string]*regexp.Regexp) bool {
	for _, e := range entries {
		if !attrOK(e.attrs, want) {
			continue
		}
		switch e.typ {
		case "domain":
			if host == e.value || strings.HasSuffix(host, "."+e.value) {
				return true
			}
		case "full":
			if host == e.value {
				return true
			}
		case "keyword":
			if strings.Contains(host, e.value) {
				return true
			}
		case "regexp":
			re := res[e.value]
			if re == nil {
				re = regexp.MustCompile(e.value)
				res[e.value] = re
			}
			if re.MatchString(host) {
				return true
			}
		}
	}
	return false
}

func TestXCheckGeositeAgainstSource(t *testing.T) {
	dir, n := xcheckEnv(t)
	b, err := os.ReadFile(filepath.Join(dir, "geosite.dat"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	db, err := parseGeositeDB(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("geosite.dat: %d bytes, %d categories, indexed in %v", len(b), len(db.index), time.Since(start).Round(time.Millisecond))
	dlc := newDLC(t, filepath.Join(dir, "dlc-src", "data"))
	res := map[string]*regexp.Regexp{}
	for _, key := range []string{"google", "google@cn", "google@!cn", "apple", "apple@cn", "microsoft@cn", "category-ads-all", "github", "netflix", "telegram", "cn", "geolocation-!cn", "geolocation-!cn@cn", "category-games@cn", "steam@cn"} {
		parts := strings.Split(key, "@")
		cat := parts[0]
		var want []string
		for _, a := range parts[1:] {
			want = append(want, strings.Replace(a, "!", "-", 1))
		}
		entries := dlcPolish(dlc.resolve(t, cat, 0))
		var exact, suffix, kw []string
		for _, e := range entries {
			switch e.typ {
			case "full":
				exact = append(exact, e.value)
			case "domain":
				suffix = append(suffix, e.value)
			case "keyword":
				kw = append(kw, e.value)
			}
		}
		rng := rand.New(rand.NewSource(int64(len(key))))
		start := time.Now()
		m := db.matcher(key)
		compile := time.Since(start)
		if m.missing {
			t.Fatalf("%s: category missing", key)
		}
		samples := domainSamples(rng, exact, suffix, kw, n)
		mismatch, hits := 0, 0
		for _, s := range samples {
			ref := dlcMatch(entries, want, s, res)
			if ref {
				hits++
			}
			if m.dom.match(s) != ref {
				mismatch++
				if mismatch <= 10 {
					t.Errorf("%s %q: kat=%v source=%v", key, s, !ref, ref)
				}
			}
		}
		t.Logf("geosite %-22s source entries=%6d samples=%d matches=%d mismatches=%d (compiled in %v)", key, len(entries), len(samples), hits, mismatch, compile.Round(time.Microsecond))
	}
}

// ---- 5. ASN rules vs the mmdb networks ----

func TestXCheckASN(t *testing.T) {
	dir, n := xcheckEnv(t)
	p := filepath.Join(dir, "GeoLite2-ASN.mmdb")
	r, err := maxminddb.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	type netASN struct {
		n   *net.IPNet
		asn uint32
	}
	var all []netASN
	it := r.Networks(maxminddb.SkipAliasedNetworks)
	for it.Next() {
		var rec asnRecord
		nw, err := it.Network(&rec)
		if err != nil {
			t.Fatal(err)
		}
		if rec.ASN != 0 {
			all = append(all, netASN{nw, rec.ASN})
		}
	}
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	if len(all) > n {
		all = all[:n]
	}
	asnOpt := &GeoIPOptions{Path: p}
	mismatch := 0
	// Known anchors through the whole Decide path.
	anchors := map[string]uint32{"1.1.1.1": 13335, "8.8.8.8": 15169, "2606:4700:4700::1111": 13335, "2001:4860:4860::8888": 15169}
	for s, asn := range anchors {
		e := mustEngine(t, Options{Rules: []Rule{{IPASN: "AS" + strconv.Itoa(int(asn)), Outbound: "hit", NoResolve: true}}, ASN: asnOpt}, nil)
		if d := decideIP(t, e, s, 443); d.Outbound != "hit" {
			mismatch++
			t.Errorf("anchor %s AS%d: %+v", s, asn, d)
		}
	}
	// Random networks: the rule conditions of the same engine.
	e := mustEngine(t, Options{Rules: []Rule{{IPASN: "1", Outbound: "hit", NoResolve: true}}, ASN: asnOpt}, nil)
	for _, x := range all {
		a, _ := netip.AddrFromSlice(x.n.IP)
		a = a.Unmap()
		dst := e.match(&cond{kind: kIPASN, num: x.asn}, &query{}, &ipInfo{ip: a})
		src := e.match(&cond{kind: kSrcIPASN, num: x.asn}, &query{src: a}, nil)
		other := e.match(&cond{kind: kIPASN, num: x.asn + 1}, &query{}, &ipInfo{ip: a})
		if !dst || !src || other {
			mismatch++
			if mismatch < 10 {
				t.Errorf("%s (%s) AS%d: dst=%v src=%v other=%v", a, x.n, x.asn, dst, src, other)
			}
		}
	}
	t.Logf("ASN: %d anchors + %d random networks checked (dst, src, other ASN), %d mismatches", len(anchors), len(all), mismatch)
}
