package route

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// ---- v2fly geosite.dat (protobuf GeoSiteList) ----
//
//	message Domain    { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//	message Attribute { string key = 1; oneof typed_value { bool bool_value = 2; int64 int_value = 3; } }
//	message GeoSite   { string country_code = 1; repeated Domain domain = 2; ... }
//	message GeoSiteList { repeated GeoSite entry = 1; }
//
// Type: Plain = 0 (keyword), Regex = 1, Domain = 2 (domain and subdomains),
// Full = 3 (exact). A minimal wire decoder is enough: only length-delimited
// and varint fields are used, unknown fields are skipped.

type siteSource struct {
	src *source
	db  atomic.Pointer[siteDB]
}

// siteDB keeps the raw file and the byte range of every category; a
// category (with its attribute filter) is compiled on first use.
type siteDB struct {
	index    map[string][]byte // lower-case category -> GeoSite message
	compiled sync.Map          // key (category[@attr...]) -> *siteMatcher
}

type siteMatcher struct {
	dom     domainSet
	missing bool
}

var errProto = errors.New("route: malformed protobuf")

// protoField reads one field header and value. For wire type 2 val is the
// payload; for wire type 0 num is the varint. Groups are rejected.
func protoField(b []byte) (field uint64, wire uint8, num uint64, val []byte, rest []byte, err error) {
	key, n := binary.Uvarint(b)
	if n <= 0 || key>>3 == 0 {
		return 0, 0, 0, nil, nil, errProto
	}
	b = b[n:]
	field, wire = key>>3, uint8(key&7)
	switch wire {
	case 0:
		num, n = binary.Uvarint(b)
		if n <= 0 {
			return 0, 0, 0, nil, nil, errProto
		}
		b = b[n:]
	case 1:
		if len(b) < 8 {
			return 0, 0, 0, nil, nil, errProto
		}
		b = b[8:]
	case 2:
		l, n := binary.Uvarint(b)
		if n <= 0 || l > uint64(len(b)-n) {
			return 0, 0, 0, nil, nil, errProto
		}
		val = b[n : n+int(l)]
		b = b[n+int(l):]
	case 5:
		if len(b) < 4 {
			return 0, 0, 0, nil, nil, errProto
		}
		b = b[4:]
	default:
		return 0, 0, 0, nil, nil, errProto
	}
	return field, wire, num, val, b, nil
}

func parseGeositeDB(b []byte) (*siteDB, error) {
	db := &siteDB{index: map[string][]byte{}}
	for len(b) > 0 {
		f, w, _, val, rest, err := protoField(b)
		if err != nil {
			return nil, errParse
		}
		b = rest
		if f != 1 || w != 2 {
			continue
		}
		// Category name: field 1 of the GeoSite message.
		name := ""
		m := val
		for len(m) > 0 {
			f2, w2, _, v2, r2, err := protoField(m)
			if err != nil {
				return nil, errParse
			}
			m = r2
			if f2 == 1 && w2 == 2 {
				name = strings.ToLower(string(v2))
			}
		}
		if name == "" {
			return nil, errParse
		}
		db.index[name] = val
	}
	if len(db.index) == 0 {
		return nil, errParse
	}
	return db, nil
}

// matcher returns the compiled matcher for "category[@attr...]" (never nil).
func (db *siteDB) matcher(key string) *siteMatcher {
	if v, ok := db.compiled.Load(key); ok {
		return v.(*siteMatcher)
	}
	m := db.compile(key)
	v, _ := db.compiled.LoadOrStore(key, m)
	return v.(*siteMatcher)
}

func (db *siteDB) compile(key string) *siteMatcher {
	parts := strings.Split(key, "@")
	msg, ok := db.index[parts[0]]
	if !ok {
		return &siteMatcher{missing: true}
	}
	attrs := parts[1:]
	sm := &siteMatcher{}
	d := &sm.dom
	for len(msg) > 0 {
		f, w, _, val, rest, err := protoField(msg)
		if err != nil {
			break
		}
		msg = rest
		if f != 2 || w != 2 {
			continue
		}
		typ, value, has, ok := decodeSiteDomain(val)
		if !ok || !attrMatch(attrs, has) {
			continue
		}
		value = strings.ToLower(value)
		switch typ {
		case 0:
			if k, ok := normKeyword(value); ok {
				d.keywords = append(d.keywords, k)
			}
		case 1:
			if re, err := compileDomainRegex(value); err == nil {
				d.regex = append(d.regex, re)
			}
		case 2:
			if v, ok := normDomain(value); ok {
				put(&d.suffix, v)
			}
		case 3:
			if v, ok := normDomain(value); ok {
				put(&d.exact, v)
			}
		}
	}
	return sm
}

func decodeSiteDomain(b []byte) (typ uint64, value string, attrs []string, ok bool) {
	for len(b) > 0 {
		f, w, num, val, rest, err := protoField(b)
		if err != nil {
			return 0, "", nil, false
		}
		b = rest
		switch {
		case f == 1 && w == 0:
			typ = num
		case f == 2 && w == 2:
			value = string(val)
		case f == 3 && w == 2:
			a := val
			for len(a) > 0 {
				f3, w3, _, v3, r3, err := protoField(a)
				if err != nil {
					return 0, "", nil, false
				}
				a = r3
				if f3 == 1 && w3 == 2 {
					attrs = append(attrs, strings.ToLower(string(v3)))
				}
			}
		}
	}
	return typ, value, attrs, value != ""
}

// attrMatch: every "attr" must be present and every "!attr" absent.
func attrMatch(want, has []string) bool {
	for _, w := range want {
		neg := strings.HasPrefix(w, "!")
		w = strings.TrimPrefix(w, "!")
		found := false
		for _, h := range has {
			if h == w {
				found = true
				break
			}
		}
		if found == neg {
			return false
		}
	}
	return true
}

func (e *Engine) siteMatch(key, host string) bool {
	if e.site == nil {
		return false
	}
	db := e.site.db.Load()
	if db == nil {
		return false
	}
	return db.matcher(key).dom.match(host)
}

// geositeRefs lists the geosite keys used by the configured rules.
func geositeRefs(rules []Rule) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(r *Rule)
	walk = func(r *Rule) {
		if r.Geosite != "" && !seen[r.Geosite] {
			seen[r.Geosite] = true
			out = append(out, r.Geosite)
		}
		for i := range r.And {
			walk(&r.And[i])
		}
		for i := range r.Or {
			walk(&r.Or[i])
		}
		if r.Not != nil {
			walk(r.Not)
		}
	}
	for i := range rules {
		walk(&rules[i])
	}
	return out
}

// ---- ASN (MaxMind DB, e.g. GeoLite2-ASN) ----

type asnSource struct {
	src *source
	db  atomic.Pointer[asnDB]
}

type asnDB struct{ r *maxminddb.Reader }

type asnRecord struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
}

func parseASNDB(b []byte) (db *asnDB, err error) {
	defer func() {
		if recover() != nil {
			db, err = nil, errParse
		}
	}()
	r, e := maxminddb.FromBytes(b)
	if e != nil || r.Metadata.NodeCount == 0 || r.Metadata.IPVersion != 4 && r.Metadata.IPVersion != 6 {
		return nil, errParse
	}
	for _, p := range []string{"1.1.1.1", "8.8.8.8"} {
		var rec asnRecord
		if r.Lookup(net.ParseIP(p), &rec) != nil {
			return nil, errParse
		}
	}
	return &asnDB{r: r}, nil
}

func (a *asnDB) lookup(ip netip.Addr) (n uint32) {
	defer func() {
		if recover() != nil {
			n = 0
		}
	}()
	var rec asnRecord
	if a.r.Lookup(net.IP(ip.AsSlice()), &rec) != nil {
		return 0
	}
	return rec.ASN
}
