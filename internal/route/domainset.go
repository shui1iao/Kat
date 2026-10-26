package route

import (
	"regexp"
	"strings"
)

// ---- domains: exact/suffix maps (label-suffix walk), then linear lists ----

type domainSet struct {
	exact, suffix map[string]struct{}
	sub           map[string]struct{} // proper subdomains only (".x" in mihomo/sing-box)
	wild1         map[string]struct{} // "*.x": exactly one label followed by x
	keywords      []string
	globs         []string   // DOMAIN-WILDCARD: '*' any run, '?' one character
	labelPats     [][]string // other mihomo '*' label wildcards
	regex         []*regexp.Regexp
}

func put(m *map[string]struct{}, k string) {
	if *m == nil {
		*m = map[string]struct{}{}
	}
	(*m)[k] = struct{}{}
}

func (d *domainSet) empty() bool {
	return len(d.exact)+len(d.suffix)+len(d.sub)+len(d.wild1)+len(d.keywords)+len(d.globs)+len(d.labelPats)+len(d.regex) == 0
}

func (d *domainSet) match(host string) bool {
	if host == "" {
		return false
	}
	if _, ok := d.exact[host]; ok {
		return true
	}
	if len(d.suffix)+len(d.sub)+len(d.wild1) > 0 {
		first := true
		for s := host; ; {
			if _, ok := d.suffix[s]; ok {
				return true
			}
			if !first {
				if _, ok := d.sub[s]; ok {
					return true
				}
			}
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
			if first && len(d.wild1) > 0 {
				if _, ok := d.wild1[s]; ok {
					return true
				}
			}
			first = false
		}
	}
	for _, k := range d.keywords {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, g := range d.globs {
		if wildcardMatch(g, host) {
			return true
		}
	}
	if len(d.labelPats) > 0 {
		labels := strings.Split(host, ".")
		for _, p := range d.labelPats {
			if labelPatMatch(p, labels) {
				return true
			}
		}
	}
	for _, re := range d.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func labelPatMatch(p, labels []string) bool {
	if len(p) != len(labels) {
		return false
	}
	for i := range p {
		if p[i] != "*" && p[i] != labels[i] {
			return false
		}
	}
	return true
}

// Domain list dialects.
const (
	dialKat   = iota // Kat 0.6 text: "+.x" and ".x" = x and subdomains, "*" label wildcard
	dialMihom        // mihomo: "+.x" = x and subdomains, ".x" = subdomains only, "*" label wildcard
	dialSurge        // Surge DOMAIN-SET: ".x" = x and subdomains, otherwise exact
)

// addDomainEntry adds one domain-list entry; false = malformed.
func (d *domainSet) addDomainEntry(s string, dialect int) bool {
	switch {
	case dialect != dialSurge && strings.HasPrefix(s, "+."):
		v, ok := normDomain(s[2:])
		if !ok {
			return false
		}
		put(&d.suffix, v)
		return true
	case strings.HasPrefix(s, "."):
		v, ok := normDomain(s[1:])
		if !ok {
			return false
		}
		if dialect == dialMihom {
			put(&d.sub, v)
		} else {
			put(&d.suffix, v)
		}
		return true
	case strings.IndexByte(s, '*') >= 0:
		if dialect == dialSurge {
			return false
		}
		return d.addLabelWildcard(s)
	}
	v, ok := normDomain(s)
	if !ok {
		return false
	}
	put(&d.exact, v)
	return true
}

// addLabelWildcard: labels are "*" (exactly one label) or ordinary labels.
func (d *domainSet) addLabelWildcard(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "*" {
			continue
		}
		if _, ok := normDomain(l); !ok || strings.IndexByte(l, '*') >= 0 {
			return false
		}
	}
	if len(labels) < 2 {
		return false
	}
	rest := strings.Join(labels[1:], ".")
	if labels[0] == "*" && strings.IndexByte(rest, '*') < 0 {
		put(&d.wild1, rest)
		return true
	}
	d.labelPats = append(d.labelPats, labels)
	return true
}
