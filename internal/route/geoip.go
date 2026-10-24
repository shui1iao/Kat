package route

import (
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// privateSet is the built-in "private" geoip class (no database needed):
// unspecified/this-network, RFC 1918, CGNAT, loopback, link-local, IETF
// protocol assignments, documentation and benchmarking nets, multicast,
// reserved/broadcast; IPv6 unspecified, loopback, ULA, link-local, multicast
// and documentation.
var privateSet = func() ipSet {
	var s ipSet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		s.add(netip.MustParsePrefix(c))
	}
	s.build()
	return s
}()

func isPrivate(ip netip.Addr) bool { return privateSet.contains(ip) }

type geoDB struct {
	r *maxminddb.Reader
}

type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// parseGeoIP opens an in-memory MaxMind DB and sanity-checks it with probe
// lookups so that a corrupt download never replaces a working database.
func parseGeoIP(b []byte) (db *geoDB, err error) {
	defer func() {
		if recover() != nil {
			db, err = nil, errParse
		}
	}()
	r, e := maxminddb.FromBytes(b)
	if e != nil || r.Metadata.NodeCount == 0 || r.Metadata.IPVersion != 4 && r.Metadata.IPVersion != 6 {
		return nil, errParse
	}
	probes := []string{"1.1.1.1", "8.8.8.8", "223.5.5.5"}
	if r.Metadata.IPVersion == 6 {
		probes = append(probes, "2001:4860:4860::8888", "2400:3200::1")
	}
	for _, p := range probes {
		var rec geoRecord
		if r.Lookup(net.ParseIP(p), &rec) != nil {
			return nil, errParse
		}
	}
	return &geoDB{r: r}, nil
}

// country returns the upper-case ISO code from country.iso_code, falling back
// to registered_country.iso_code; "" when unknown.
func (g *geoDB) country(ip netip.Addr) (code string) {
	defer func() {
		if recover() != nil {
			code = ""
		}
	}()
	var rec geoRecord
	if g.r.Lookup(net.IP(ip.AsSlice()), &rec) != nil {
		return ""
	}
	c := rec.Country.ISOCode
	if c == "" {
		c = rec.RegisteredCountry.ISOCode
	}
	return strings.ToUpper(c)
}
