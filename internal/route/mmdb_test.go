package route

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

// ---- minimal MaxMind DB writer (from the public MaxMind DB format spec v2.0) ----
//
// Layout: binary search tree (record size 24, IPv6 tree with IPv4 under
// ::/96) | 16 zero bytes | data section | "\xAB\xCD\xEFMaxMind.com" | metadata map.

type mmU16 uint16
type mmU32 uint32
type mmU64 uint64
type mmPair struct {
	k string
	v any
}
type mmMap []mmPair

func mmCtrl(typ, size int) []byte {
	first := byte(typ << 5)
	var ext []byte
	if typ > 7 {
		first = 0
		ext = []byte{byte(typ - 7)}
	}
	var sz []byte
	switch {
	case size < 29:
		first |= byte(size)
	case size < 29+256:
		first |= 29
		sz = []byte{byte(size - 29)}
	case size < 285+65536:
		first |= 30
		v := size - 285
		sz = []byte{byte(v >> 8), byte(v)}
	default:
		first |= 31
		v := size - 65821
		sz = []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return append(append([]byte{first}, ext...), sz...)
}

func mmUint(typ int, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 8 && b[i] == 0 {
		i++
	}
	return append(mmCtrl(typ, 8-i), b[i:]...)
}

func mmEncode(v any) []byte {
	switch x := v.(type) {
	case string:
		return append(mmCtrl(2, len(x)), x...)
	case mmU16:
		return mmUint(5, uint64(x))
	case mmU32:
		return mmUint(6, uint64(x))
	case mmU64:
		return mmUint(9, uint64(x))
	case mmMap:
		out := mmCtrl(7, len(x))
		for _, p := range x {
			out = append(out, mmEncode(p.k)...)
			out = append(out, mmEncode(p.v)...)
		}
		return out
	case []any:
		out := mmCtrl(11, len(x))
		for _, e := range x {
			out = append(out, mmEncode(e)...)
		}
		return out
	}
	panic("unsupported mmdb value")
}

type mmNode struct {
	child [2]*mmNode
	data  int // index into records, -1 for internal/empty
}

// buildMMDB maps (non-overlapping) prefixes to records.
func buildMMDB(t *testing.T, nets map[string]int, records []mmMap) []byte {
	t.Helper()
	root := &mmNode{data: -1}
	for cidr, rec := range nets {
		p := netip.MustParsePrefix(cidr)
		ip16 := p.Addr().As16()
		bits := p.Bits()
		if p.Addr().Is4() {
			ip16 = [16]byte{}
			a4 := p.Addr().As4()
			copy(ip16[12:], a4[:])
			bits += 96
		}
		n := root
		for i := 0; i < bits; i++ {
			b := ip16[i/8] >> (7 - i%8) & 1
			if n.child[b] == nil {
				n.child[b] = &mmNode{data: -1}
			}
			n = n.child[b]
		}
		n.data = rec
	}
	// Number internal nodes breadth-first.
	var order []*mmNode
	id := map[*mmNode]int{}
	queue := []*mmNode{root}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		id[n] = len(order)
		order = append(order, n)
		for _, c := range n.child {
			if c != nil && c.data < 0 {
				queue = append(queue, c)
			}
		}
	}
	nodeCount := len(order)
	var data []byte
	offsets := make([]int, len(records))
	for i, r := range records {
		offsets[i] = len(data)
		data = append(data, mmEncode(r)...)
	}
	var tree []byte
	rec := func(c *mmNode) int {
		switch {
		case c == nil:
			return nodeCount
		case c.data >= 0:
			return nodeCount + 16 + offsets[c.data]
		}
		return id[c]
	}
	for _, n := range order {
		for _, c := range n.child {
			v := rec(c)
			tree = append(tree, byte(v>>16), byte(v>>8), byte(v))
		}
	}
	var out bytes.Buffer
	out.Write(tree)
	out.Write(make([]byte, 16))
	out.Write(data)
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	out.Write(mmEncode(mmMap{
		{"binary_format_major_version", mmU16(2)},
		{"binary_format_minor_version", mmU16(0)},
		{"build_epoch", mmU64(1761264000)},
		{"database_type", "Kat-Test-Country"},
		{"description", mmMap{{"en", "Kat route package test database"}}},
		{"ip_version", mmU16(6)},
		{"languages", []any{"en"}},
		{"node_count", mmU32(nodeCount)},
		{"record_size", mmU16(24)},
	}))
	return out.Bytes()
}

func country(code string) mmMap { return mmMap{{"iso_code", code}} }

// testMMDB: v4 and v6 networks; one record with only registered_country; one
// with both (country wins).
func testMMDB(t *testing.T) []byte {
	return buildMMDB(t, map[string]int{
		"1.0.1.0/24":     0,
		"8.8.8.0/24":     1,
		"2001:da8::/32":  0,
		"2001:4860::/32": 1,
		"133.0.0.0/8":    2,
	}, []mmMap{
		{{"country", country("CN")}, {"registered_country", country("CN")}},
		{{"registered_country", country("US")}},
		{{"country", country("JP")}, {"registered_country", country("US")}},
	})
}

func TestMMDBGeneratorOpensWithMaxminddb(t *testing.T) {
	p := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(p, testMMDB(t), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := maxminddb.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		t.Fatal("generated database fails maxminddb verification:", err)
	}
	var rec geoRecord
	if err := r.Lookup(net.ParseIP("1.0.1.9"), &rec); err != nil || rec.Country.ISOCode != "CN" {
		t.Fatal(rec, err)
	}
	n := 0
	for it := r.Networks(); it.Next(); {
		n++
	}
	t.Logf("generated mmdb: %d networks, node_count=%d, ip_version=%d, type=%s", n, r.Metadata.NodeCount, r.Metadata.IPVersion, r.Metadata.DatabaseType)
}

func TestGeoIPRules(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "country.mmdb")
	os.WriteFile(p, testMMDB(t), 0o644)
	setPath := filepath.Join(dir, "geo-set.txt")
	os.WriteFile(setPath, []byte("GEOIP,JP\nGEOIP,LAN,no-resolve\n"), 0o644)
	ev := &eventLog{}
	e := mustEngine(t, Options{
		Rules: []Rule{
			{GeoIP: "cn", Outbound: "cn"},
			{GeoIP: "US", Outbound: "us"},
			{RuleSet: "g", Outbound: "set"},
		},
		RuleSets: []RuleSetOptions{{Name: "g", Format: "classical", Path: setPath}},
		GeoIP:    &GeoIPOptions{Path: p},
	}, ev)
	if ev.count("geoip_loaded") != 1 {
		t.Fatal(ev.all())
	}
	for ip, want := range map[string]string{
		"1.0.1.5":        "cn", // country.iso_code
		"::ffff:1.0.1.5": "cn", // mapped literal
		"2001:da8::1":    "cn", // IPv6 network
		"8.8.8.8":        "us", // registered_country fallback
		"2001:4860::8":   "us",
		"133.1.2.3":      "set", // country JP wins over registered US
		"192.168.1.1":    "set", // GEOIP,LAN (private) in classical, no database needed
		"9.9.9.9":        "",    // unknown -> final direct
		"2400:cb00::1":   "",
	} {
		d := decideIP(t, e, ip, 443)
		if d.Outbound != want || want == "" && d.Kind != Direct {
			t.Fatalf("%s: got %+v want %q", ip, d, want)
		}
	}
	dns := &fakeDNS{ips: addrs("9.9.9.9", "1.0.1.1")}
	if d, _ := decideHost(t, e, "cn.example", 443, dns); d.Kind != Direct || len(d.Candidates) != 1 || dns.calls.Load() != 1 {
		t.Fatal("first candidate decides (unknown -> direct)", d)
	}
}

func TestGeoIPMissingOrCorruptDatabase(t *testing.T) {
	dir := t.TempDir()
	ev := &eventLog{}
	e := mustEngine(t, Options{
		Rules: []Rule{{GeoIP: "CN", Action: "reject"}, {GeoIP: "private", Outbound: "lan"}},
		Final: "proxy",
		GeoIP: &GeoIPOptions{Path: filepath.Join(dir, "missing.mmdb")},
	}, ev)
	if ev.count("geoip_update_failed", "class", "missing") != 1 {
		t.Fatal(ev.all())
	}
	dns := &fakeDNS{ips: addrs("1.0.1.1")}
	if d, _ := decideHost(t, e, "x.example", 443, dns); d.Outbound != "proxy" || dns.calls.Load() != 1 {
		// CN rule cannot match without a database and does not need DNS;
		// the private rule still does (built in).
		t.Fatal(d, dns.calls.Load())
	}
	if d := decideIP(t, e, "1.0.1.1", 443); d.Outbound != "proxy" {
		t.Fatal("geoip matched without database", d)
	}
	if d := decideIP(t, e, "10.0.0.1", 443); d.Outbound != "lan" {
		t.Fatal("private without database", d)
	}
	// No geoip block at all: private works.
	e2 := mustEngine(t, Options{Rules: []Rule{{GeoIP: "private", Action: "reject"}}}, nil)
	for _, ip := range []string{"10.1.1.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1"} {
		if decideIP(t, e2, ip, 1).Kind != Reject {
			t.Fatal("private", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "100.128.0.1", "172.32.0.1", "2400::1"} {
		if decideIP(t, e2, ip, 1).Kind != Direct {
			t.Fatal("public", ip)
		}
	}
	// Corrupt database: parse failure event, no match.
	bad := filepath.Join(dir, "bad.mmdb")
	db := testMMDB(t)
	os.WriteFile(bad, db[:len(db)/2], 0o644)
	ev3 := &eventLog{}
	e3 := mustEngine(t, Options{Rules: []Rule{{GeoIP: "CN", Action: "reject"}}, GeoIP: &GeoIPOptions{Path: bad}}, ev3)
	if ev3.count("geoip_update_failed", "class", "parse") != 1 || decideIP(t, e3, "1.0.1.1", 1).Kind != Direct {
		t.Fatal("corrupt db", ev3.all())
	}
	if _, err := parseGeoIP([]byte("\xAB\xCD\xEFMaxMind.com garbage")); err == nil {
		t.Fatal("garbage metadata accepted")
	}
}
