package route

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

// maxInflated bounds the decompressed size of binary rule sets.
const maxInflated = 512 << 20

// ---- Clash YAML rule-provider ----

// yamlPayload returns the payload strings of a Clash rule-provider file.
func yamlPayload(b []byte) ([]string, error) {
	if _, err := textOf(b); err != nil {
		return nil, err
	}
	var doc map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, errParse
	}
	for k := range doc {
		if k != "payload" {
			return nil, unsupported("yaml rule-provider field %s", k)
		}
	}
	// A second YAML document must not be silently discarded.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errParse
	}
	payload, ok := doc["payload"].([]any)
	if !ok {
		return nil, errParse
	}
	out := make([]string, 0, len(payload))
	for i, v := range payload {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case int, int64, uint64, float64, bool:
			out = append(out, fmt.Sprint(x))
		default:
			return nil, unsupported("yaml payload[%d]: expected a scalar rule, not a structured item", i)
		}
	}
	return out, nil
}

// ---- mihomo MRS ----

func parseMRS(behavior string, b []byte, limit int) (*setData, error) {
	zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderMaxMemory(maxInflated), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, errParse
	}
	defer zr.Close()
	r := bufio.NewReader(io.LimitReader(zr, maxInflated))
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil || hdr != [4]byte{'M', 'R', 'S', 1} {
		return nil, errParse
	}
	beh, err := r.ReadByte()
	if err != nil {
		return nil, errParse
	}
	want := byte(0)
	if behavior == "ipcidr" {
		want = 1
	}
	if beh != want {
		if beh <= 2 {
			return nil, unsupported("mrs behavior %d does not match the configured behavior %s", beh, behavior)
		}
		return nil, errParse
	}
	var count, extra int64
	if binary.Read(r, binary.BigEndian, &count) != nil || binary.Read(r, binary.BigEndian, &extra) != nil || count < 0 || extra < 0 || extra > 1<<20 {
		return nil, errParse
	}
	if count > int64(limit) {
		return nil, errLimit
	}
	if _, err := io.CopyN(io.Discard, r, extra); err != nil {
		return nil, errParse
	}
	ver, err := r.ReadByte()
	if err != nil || ver != 1 {
		return nil, errParse
	}
	bld := newBuilder(limit)
	readLen := func() (int, error) {
		var n int64
		if err := binary.Read(r, binary.BigEndian, &n); err != nil || n < 0 || n > maxInflated/8 {
			return 0, errParse
		}
		return int(n), nil
	}
	if behavior == "ipcidr" {
		n, err := readLen()
		if err != nil {
			return nil, err
		}
		var buf [32]byte
		for i := 0; i < n; i++ {
			if _, err := io.ReadFull(r, buf[:]); err != nil {
				return nil, errParse
			}
			from := netip.AddrFrom16([16]byte(buf[:16]))
			to := netip.AddrFrom16([16]byte(buf[16:]))
			if !bld.d.ip.addRange(from, to) {
				bld.skip()
				continue
			}
			if err := bld.count(); err != nil {
				return nil, err
			}
		}
		return bld.finish()
	}
	readU64s := func() ([]uint64, error) {
		n, err := readLen()
		if err != nil {
			return nil, err
		}
		out := make([]uint64, n)
		if err := binary.Read(r, binary.BigEndian, out); err != nil {
			return nil, errParse
		}
		return out, nil
	}
	leaves, err := readU64s()
	if err != nil {
		return nil, err
	}
	bm, err := readU64s()
	if err != nil {
		return nil, err
	}
	n, err := readLen()
	if err != nil {
		return nil, err
	}
	labels := make([]byte, n)
	if _, err := io.ReadFull(r, labels); err != nil {
		return nil, errParse
	}
	d := &bld.d.dom
	err = louds(leaves, bm, labels, limit, func(k []byte) error {
		key := reverseRunes(k)
		ok := false
		switch {
		case strings.HasPrefix(key, "+."):
			var v string
			if v, ok = normDomain(key[2:]); ok {
				put(&d.sub, v)
			}
		case strings.IndexByte(key, '*') >= 0:
			ok = d.addLabelWildcard(key)
		default:
			var v string
			if v, ok = normDomain(key); ok {
				put(&d.exact, v)
			}
		}
		if !ok {
			bld.skip()
			return nil
		}
		return bld.count()
	})
	if err != nil {
		if errors.Is(err, errLimit) {
			return nil, err
		}
		return nil, errParse
	}
	// x plus its proper subdomains is a suffix entry.
	for k := range d.sub {
		if _, ok := d.exact[k]; ok {
			delete(d.exact, k)
			delete(d.sub, k)
			put(&d.suffix, k)
		}
	}
	return bld.finish()
}

// ---- sing-box SRS ----

const (
	srsQueryType uint8 = iota
	srsNetwork
	srsDomain
	srsDomainKeyword
	srsDomainRegex
	srsSourceIPCIDR
	srsIPCIDR
	srsSourcePort
	srsSourcePortRange
	srsPort
	srsPortRange
	srsProcessName
	srsProcessPath
	srsPackageName
	srsWIFISSID
	srsWIFIBSSID
	srsAdGuardDomain
	srsProcessPathRegex
	srsNetworkType
	srsNetworkIsExpensive
	srsNetworkIsConstrained
	srsNetworkInterfaceAddress
	srsDefaultInterfaceAddress
	srsPackageNameRegex
	srsFinal uint8 = 0xFF
)

var srsItemNames = map[uint8]string{
	srsQueryType: "query_type", srsProcessName: "process_name", srsProcessPath: "process_path",
	srsPackageName: "package_name", srsWIFISSID: "wifi_ssid", srsWIFIBSSID: "wifi_bssid",
	srsAdGuardDomain: "adguard_domain", srsProcessPathRegex: "process_path_regex",
	srsNetworkType: "network_type", srsNetworkIsExpensive: "network_is_expensive",
	srsNetworkIsConstrained: "network_is_constrained", srsNetworkInterfaceAddress: "network_interface_address",
	srsDefaultInterfaceAddress: "default_interface_address", srsPackageNameRegex: "package_name_regex",
}

// sbRule is one sing-box default rule mapped to Kat conditions.
type sbRule struct {
	dest     *setBuilder // domains, keywords, regexes, ip_cidr
	destN    int
	ports    []portRange
	srcIP    ipSet
	srcIPN   int
	srcPorts []portRange
	network  []string
	invert   bool
}

const maxSRSVersion = 5

func parseSRS(b []byte, limit int, env parseEnv) (*setData, error) {
	if len(b) < 4 || string(b[:3]) != "SRS" {
		return nil, errParse
	}
	if b[3] < 1 || b[3] > maxSRSVersion {
		return nil, unsupported("srs version %d", b[3])
	}
	zr, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		return nil, errParse
	}
	defer zr.Close()
	r := bufio.NewReader(io.LimitReader(zr, maxInflated))
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, errParse
	}
	bld := newBuilder(limit)
	for i := uint64(0); i < n; i++ {
		c, sb, err := readSRSRule(r, limit, 0)
		if err != nil {
			return nil, srsErr(err, fmt.Sprintf("rule[%d]", i))
		}
		if err := bld.addSB(c, sb); err != nil {
			return nil, err
		}
	}
	return bld.finish()
}

func srsErr(err error, where string) error {
	var u *unsupportedError
	if errors.As(err, &u) {
		return &unsupportedError{where + ": " + u.msg}
	}
	if errors.Is(err, errLimit) {
		return err
	}
	return errParse
}

func readSRSRule(r *bufio.Reader, limit, depth int) (*cond, *sbRule, error) {
	if depth > maxClassicalDepth {
		return nil, nil, unsupported("logical rule nested deeper than %d", maxClassicalDepth)
	}
	t, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	switch t {
	case 0:
		sb, err := readSRSDefault(r, limit)
		if err != nil {
			return nil, nil, err
		}
		return nil, sb, nil
	case 1:
		mode, err := r.ReadByte()
		if err != nil || mode > 1 {
			return nil, nil, errParse
		}
		cnt, err := binary.ReadUvarint(r)
		if err != nil || cnt == 0 || cnt > 1<<16 {
			return nil, nil, errParse
		}
		c := &cond{kind: kAnd}
		if mode == 1 {
			c.kind = kOr
		}
		for i := uint64(0); i < cnt; i++ {
			sc, sb, err := readSRSRule(r, limit, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if sb != nil {
				sc = sb.cond()
			}
			c.subs = append(c.subs, sc)
		}
		inv, err := r.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		if inv != 0 {
			c = &cond{kind: kNot, subs: []*cond{c}}
		}
		return c, nil, nil
	}
	return nil, nil, errParse
}

func readSRSStrings(r *bufio.Reader) ([]string, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil || n > maxInflated {
		return nil, errParse
	}
	out := make([]string, 0, min(n, 1<<16))
	for i := uint64(0); i < n; i++ {
		l, err := binary.ReadUvarint(r)
		if err != nil || l > 1<<16 {
			return nil, errParse
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, errParse
		}
		out = append(out, string(b))
	}
	return out, nil
}

func readSRSU16s(r *bufio.Reader) ([]uint16, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil || n > 1<<20 {
		return nil, errParse
	}
	out := make([]uint16, n)
	if err := binary.Read(r, binary.BigEndian, out); err != nil {
		return nil, errParse
	}
	return out, nil
}

func readSRSU64s(r *bufio.Reader) ([]uint64, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil || n > maxInflated/8 {
		return nil, errParse
	}
	out := make([]uint64, n)
	if err := binary.Read(r, binary.BigEndian, out); err != nil {
		return nil, errParse
	}
	return out, nil
}

func readSRSIPSet(r *bufio.Reader, f func(lo, hi netip.Addr) error) error {
	v, err := r.ReadByte()
	if err != nil || v != 1 {
		return errParse
	}
	var n uint64
	if err := binary.Read(r, binary.BigEndian, &n); err != nil || n > maxInflated/8 {
		return errParse
	}
	addr := func() (netip.Addr, error) {
		l, err := binary.ReadUvarint(r)
		if err != nil || l != 4 && l != 16 {
			return netip.Addr{}, errParse
		}
		var b [16]byte
		if _, err := io.ReadFull(r, b[:l]); err != nil {
			return netip.Addr{}, errParse
		}
		if l == 4 {
			return netip.AddrFrom4([4]byte(b[:4])), nil
		}
		return netip.AddrFrom16(b), nil
	}
	for i := uint64(0); i < n; i++ {
		lo, err := addr()
		if err != nil {
			return err
		}
		hi, err := addr()
		if err != nil {
			return err
		}
		if err := f(lo, hi); err != nil {
			return err
		}
	}
	return nil
}

func readSRSDefault(r *bufio.Reader, limit int) (*sbRule, error) {
	sb := &sbRule{dest: newBuilder(limit)}
	for {
		item, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch item {
		case srsFinal:
			inv, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			sb.invert = inv != 0
			return sb, nil
		case srsNetwork:
			l, err := readSRSStrings(r)
			if err != nil {
				return nil, err
			}
			for _, v := range l {
				v = strings.ToLower(v)
				if v != "tcp" && v != "udp" {
					return nil, unsupported("network %q", v)
				}
				sb.network = append(sb.network, v)
			}
		case srsDomain:
			if _, err := r.ReadByte(); err != nil { // succinct set version
				return nil, err
			}
			leaves, err := readSRSU64s(r)
			if err != nil {
				return nil, err
			}
			bm, err := readSRSU64s(r)
			if err != nil {
				return nil, err
			}
			ln, err := binary.ReadUvarint(r)
			if err != nil || ln > maxInflated {
				return nil, errParse
			}
			labels := make([]byte, ln)
			if _, err := io.ReadFull(r, labels); err != nil {
				return nil, errParse
			}
			d := &sb.dest.d.dom
			err = louds(leaves, bm, labels, limit, func(k []byte) error {
				key := reverseRunes(k)
				ok := false
				var v string
				switch {
				case strings.HasPrefix(key, "\r."):
					if v, ok = normDomain(key[2:]); ok {
						put(&d.sub, v)
					}
				case strings.HasPrefix(key, "\n"):
					if v, ok = normDomain(key[1:]); ok {
						put(&d.suffix, v)
					}
				default:
					if v, ok = normDomain(key); ok {
						put(&d.exact, v)
					}
				}
				if !ok {
					sb.dest.skip()
					return nil
				}
				sb.destN++
				return sb.dest.count()
			})
			if err != nil {
				return nil, err
			}
			for k := range d.sub {
				if _, ok := d.exact[k]; ok {
					delete(d.exact, k)
					delete(d.sub, k)
					put(&d.suffix, k)
				}
			}
		case srsDomainKeyword, srsDomainRegex:
			l, err := readSRSStrings(r)
			if err != nil {
				return nil, err
			}
			for _, v := range l {
				if err := sb.addDestString(item, v); err != nil {
					return nil, err
				}
			}
		case srsSourceIPCIDR, srsIPCIDR:
			err := readSRSIPSet(r, func(lo, hi netip.Addr) error {
				if item == srsIPCIDR {
					if !sb.dest.d.ip.addRange(lo, hi) {
						return errParse
					}
					sb.destN++
					return sb.dest.count()
				}
				if !sb.srcIP.addRange(lo, hi) {
					return errParse
				}
				sb.srcIPN++
				return nil
			})
			if err != nil {
				return nil, err
			}
		case srsSourcePort, srsPort:
			l, err := readSRSU16s(r)
			if err != nil {
				return nil, err
			}
			for _, p := range l {
				sb.addPort(item == srsSourcePort, portRange{p, p})
			}
		case srsSourcePortRange, srsPortRange:
			l, err := readSRSStrings(r)
			if err != nil {
				return nil, err
			}
			for _, v := range l {
				pr, ok := sbPortRange(v)
				if !ok {
					return nil, errParse
				}
				sb.addPort(item == srsSourcePortRange, pr)
			}
		default:
			if name, ok := srsItemNames[item]; ok {
				return nil, unsupported("sing-box field %s", name)
			}
			return nil, unsupported("sing-box rule item type %d", item)
		}
	}
}

func (sb *sbRule) addPort(src bool, p portRange) {
	if src {
		sb.srcPorts = append(sb.srcPorts, p)
	} else {
		sb.ports = append(sb.ports, p)
	}
}

func (sb *sbRule) addDestString(item uint8, v string) error {
	d := sb.dest.d
	if item == srsDomainKeyword {
		k, ok := normKeyword(v)
		if !ok {
			sb.dest.skip()
			return nil
		}
		d.dom.keywords = append(d.dom.keywords, k)
	} else {
		re, err := compileDomainRegex(v)
		if err != nil {
			return unsupported("domain_regex %q: %v", v, err)
		}
		d.dom.regex = append(d.dom.regex, re)
	}
	sb.destN++
	return sb.dest.count()
}

// sbPortRange parses sing-box "a:b", ":b" or "a:".
func sbPortRange(s string) (portRange, bool) {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return portRange{}, false
	}
	lo, hi := uint64(0), uint64(65535)
	var err error
	if a != "" {
		if lo, err = strconv.ParseUint(a, 10, 16); err != nil {
			return portRange{}, false
		}
	}
	if b != "" {
		if hi, err = strconv.ParseUint(b, 10, 16); err != nil {
			return portRange{}, false
		}
	}
	if lo > hi {
		return portRange{}, false
	}
	return portRange{uint16(lo), uint16(hi)}, true
}

// onlyDest reports whether the rule is a plain destination list.
func (sb *sbRule) onlyDest() bool {
	return !sb.invert && len(sb.ports) == 0 && sb.srcIPN == 0 && len(sb.srcPorts) == 0 && len(sb.network) == 0
}

// cond converts the rule: the AND of its groups, each group an OR.
func (sb *sbRule) cond() *cond {
	var parts []*cond
	if sb.destN > 0 {
		d := sb.dest.d
		d.ip.build()
		parts = append(parts, &cond{kind: kInline, inline: d})
	}
	if len(sb.ports) > 0 {
		parts = append(parts, &cond{kind: kDstPort, ports: sb.ports})
	}
	if sb.srcIPN > 0 {
		sb.srcIP.build()
		s := sb.srcIP
		parts = append(parts, &cond{kind: kSrcIPSet, ipset: &s})
	}
	if len(sb.srcPorts) > 0 {
		parts = append(parts, &cond{kind: kSrcPort, ports: sb.srcPorts})
	}
	if len(sb.network) == 1 {
		parts = append(parts, &cond{kind: kNetwork, s: sb.network[0]})
	}
	var c *cond
	switch len(parts) {
	case 0:
		c = &cond{kind: kAnd} // matches everything (empty AND)
	case 1:
		c = parts[0]
	default:
		c = &cond{kind: kAnd, subs: parts}
	}
	if sb.invert {
		c = &cond{kind: kNot, subs: []*cond{c}}
	}
	return c
}

// addSB adds one top-level sing-box rule (default rule sb or logical c).
func (b *setBuilder) addSB(c *cond, sb *sbRule) error {
	if sb != nil && sb.onlyDest() {
		// Merge into the indexes: the rule set is an OR of its rules.
		src := sb.dest.d
		d := b.d
		for k := range src.dom.exact {
			put(&d.dom.exact, k)
		}
		for k := range src.dom.suffix {
			put(&d.dom.suffix, k)
		}
		for k := range src.dom.sub {
			put(&d.dom.sub, k)
		}
		d.dom.keywords = append(d.dom.keywords, src.dom.keywords...)
		d.dom.regex = append(d.dom.regex, src.dom.regex...)
		d.ip.v4 = append(d.ip.v4, src.ip.v4...)
		d.ip.v6 = append(d.ip.v6, src.ip.v6...)
		d.skipped += sb.dest.d.skipped
		b.bad += sb.dest.bad
		d.entries += sb.destN
		if d.entries > b.limit {
			return errLimit
		}
		return nil
	}
	if sb != nil {
		c = sb.cond()
		b.d.skipped += sb.dest.d.skipped
	}
	if err := b.addCond(c); err != nil {
		return err
	}
	return nil
}

// ---- sing-box source JSON ----

func parseSingBoxJSON(b []byte, limit int, env parseEnv) (*setData, error) {
	if _, err := textOf(b); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil || top == nil {
		return nil, errParse
	}
	for k := range top {
		if k != "version" && k != "rules" {
			return nil, unsupported("sing-box rule-set field %s", k)
		}
	}
	var ver int
	if v, ok := top["version"]; !ok || json.Unmarshal(v, &ver) != nil {
		return nil, errParse
	}
	if ver < 1 || ver > maxSRSVersion {
		return nil, unsupported("sing-box rule-set version %d", ver)
	}
	var rules []json.RawMessage
	if v, ok := top["rules"]; ok && json.Unmarshal(v, &rules) != nil {
		return nil, errParse
	}
	bld := newBuilder(limit)
	for i, raw := range rules {
		c, sb, err := sbJSONRule(raw, limit, 0)
		if err != nil {
			return nil, srsErr(err, fmt.Sprintf("rules[%d]", i))
		}
		if err := bld.addSB(c, sb); err != nil {
			return nil, err
		}
	}
	return bld.finish()
}

// listable decodes a JSON string or array of strings (numbers for ports).
func listable(raw json.RawMessage) ([]string, error) {
	var one any
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, errParse
	}
	conv := func(v any) (string, error) {
		switch x := v.(type) {
		case string:
			return x, nil
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64), nil
		}
		return "", errParse
	}
	if l, ok := one.([]any); ok {
		out := make([]string, 0, len(l))
		for _, v := range l {
			s, err := conv(v)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	s, err := conv(one)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

func sbJSONRule(raw json.RawMessage, limit, depth int) (*cond, *sbRule, error) {
	if depth > maxClassicalDepth {
		return nil, nil, unsupported("logical rule nested deeper than %d", maxClassicalDepth)
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, nil, errParse
	}
	invert := false
	if v, ok := m["invert"]; ok {
		if json.Unmarshal(v, &invert) != nil {
			return nil, nil, errParse
		}
		delete(m, "invert")
	}
	typ := ""
	if v, ok := m["type"]; ok {
		if json.Unmarshal(v, &typ) != nil {
			return nil, nil, errParse
		}
		delete(m, "type")
	}
	switch typ {
	case "logical":
		var mode string
		var subs []json.RawMessage
		if json.Unmarshal(m["mode"], &mode) != nil || json.Unmarshal(m["rules"], &subs) != nil || len(subs) == 0 {
			return nil, nil, errParse
		}
		for k := range m {
			if k != "mode" && k != "rules" {
				return nil, nil, unsupported("sing-box logical rule field %s", k)
			}
		}
		c := &cond{}
		switch mode {
		case "and":
			c.kind = kAnd
		case "or":
			c.kind = kOr
		default:
			return nil, nil, errParse
		}
		for _, s := range subs {
			sc, sb, err := sbJSONRule(s, limit, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if sb != nil {
				sc = sb.cond()
			}
			c.subs = append(c.subs, sc)
		}
		if invert {
			c = &cond{kind: kNot, subs: []*cond{c}}
		}
		return c, nil, nil
	case "", "default":
	default:
		return nil, nil, errParse
	}
	sb := &sbRule{dest: newBuilder(limit), invert: invert}
	for k, v := range m {
		l, err := listable(v)
		if err != nil {
			return nil, nil, err
		}
		switch k {
		case "domain", "domain_suffix":
			for _, s := range l {
				ok := false
				var d string
				switch {
				case k == "domain":
					if d, ok = normDomain(s); ok {
						put(&sb.dest.d.dom.exact, d)
					}
				case strings.HasPrefix(s, "."):
					if d, ok = normDomain(s[1:]); ok {
						put(&sb.dest.d.dom.sub, d)
					}
				default:
					if d, ok = normDomain(s); ok {
						put(&sb.dest.d.dom.suffix, d)
					}
				}
				if !ok {
					sb.dest.skip()
					continue
				}
				sb.destN++
				if err := sb.dest.count(); err != nil {
					return nil, nil, err
				}
			}
		case "domain_keyword", "domain_regex":
			item := srsDomainKeyword
			if k == "domain_regex" {
				item = srsDomainRegex
			}
			for _, s := range l {
				if err := sb.addDestString(item, s); err != nil {
					return nil, nil, err
				}
			}
		case "ip_cidr", "source_ip_cidr":
			for _, s := range l {
				p, ok := parseCIDR(s, true)
				if !ok {
					sb.dest.skip()
					continue
				}
				if k == "ip_cidr" {
					sb.dest.d.ip.add(p)
					sb.destN++
					if err := sb.dest.count(); err != nil {
						return nil, nil, err
					}
				} else {
					sb.srcIP.add(p)
					sb.srcIPN++
				}
			}
		case "port", "source_port":
			for _, s := range l {
				p, ok := parsePort(s)
				if !ok {
					return nil, nil, errParse
				}
				sb.addPort(k == "source_port", portRange{p, p})
			}
		case "port_range", "source_port_range":
			for _, s := range l {
				pr, ok := sbPortRange(s)
				if !ok {
					return nil, nil, errParse
				}
				sb.addPort(k == "source_port_range", pr)
			}
		case "network":
			for _, s := range l {
				s = strings.ToLower(s)
				if s != "tcp" && s != "udp" {
					return nil, nil, unsupported("network %q", s)
				}
				sb.network = append(sb.network, s)
			}
		default:
			return nil, nil, unsupported("sing-box field %s", k)
		}
	}
	return nil, sb, nil
}
