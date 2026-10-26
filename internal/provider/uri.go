package provider

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/shui1iao/Kat/internal/outbound"
)

// parseURIBody parses a URI list, optionally base64 encoded as a whole.
func parseURIBody(b []byte) (Result, error) {
	s := string(b)
	format := FormatURI
	if !strings.Contains(s, "://") {
		d, ok := decodeBase64(s)
		if !ok || !strings.Contains(string(d), "://") {
			return Result{}, ErrFormat
		}
		s, format = string(d), "uri-base64"
	}
	r := Result{Format: format}
	entries := 0
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		entries++
		parseURI(&r, line)
	}
	if entries == 0 {
		return Result{}, ErrFormat
	}
	return r, nil
}

// uriParts is a share link split without net/url (userinfo of real links
// often contains characters net/url rejects, such as raw base64 '/' or '+').
type uriParts struct {
	scheme, userinfo, hostport, query, name string
	hasAt                                   bool
}

func splitURI(line string) (uriParts, bool) {
	var p uriParts
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok {
		return p, false
	}
	p.scheme = strings.ToLower(scheme)
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		frag := rest[i+1:]
		rest = rest[:i]
		if n, e := url.PathUnescape(frag); e == nil {
			p.name = n
		} else {
			p.name = frag
		}
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		p.query = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		p.userinfo, p.hostport, p.hasAt = rest[:i], rest[i+1:], true
	} else {
		p.hostport = rest
	}
	p.hostport = strings.TrimSuffix(p.hostport, "/")
	return p, true
}

func splitHostPort(hp string) (string, uint16, bool) {
	h, ps, e := net.SplitHostPort(hp)
	if e != nil {
		return "", 0, false
	}
	pt := port(ps)
	return h, pt, pt != 0 && h != ""
}

func unescape(s string) string {
	if v, e := url.PathUnescape(s); e == nil {
		return v
	}
	return s
}

func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func parseURI(r *Result, line string) {
	p, ok := splitURI(line)
	if !ok {
		r.skip("", "", "not a share link")
		return
	}
	q, _ := url.ParseQuery(p.query)
	switch p.scheme {
	case "ss":
		uriSS(r, p, q)
	case "trojan", "anytls":
		uriTLS(r, p, q)
	case "socks5", "socks", "socks5h":
		if truthy(q.Get("tls")) || q.Get("security") == "tls" {
			r.skip(p.name, p.scheme, "SOCKS5 over TLS is not supported")
			return
		}
		uriSocks(r, p)
	case "vmess":
		name := p.name
		if name == "" { // v2rayN: base64 JSON with the name in "ps"
			if d, ok := decodeBase64(p.hostport); ok {
				var v struct {
					PS string `json:"ps"`
				}
				if json.Unmarshal(d, &v) == nil {
					name = v.PS
				}
			}
		}
		r.skip(name, p.scheme, "unsupported type vmess")
	default:
		r.skip(p.name, p.scheme, "unsupported type "+p.scheme)
	}
}

func uriSS(r *Result, p uriParts, q url.Values) {
	var method, password, hp string
	if p.hasAt {
		hp = p.hostport
		ui := unescape(p.userinfo)
		if m, pw, ok := strings.Cut(ui, ":"); ok && !strings.ContainsAny(m, "=") {
			// SIP022 / plain form: method:password (percent-encoded)
			method, password = m, pw
		} else if d, ok := decodeBase64(ui); ok {
			m, pw, ok := strings.Cut(string(d), ":")
			if !ok {
				r.skip(p.name, "ss", "invalid userinfo")
				return
			}
			method, password = m, pw
		} else {
			r.skip(p.name, "ss", "invalid userinfo")
			return
		}
	} else {
		// legacy: ss://base64(method:password@host:port)#name
		d, ok := decodeBase64(unescape(p.hostport))
		if !ok {
			r.skip(p.name, "ss", "invalid legacy base64 body")
			return
		}
		s := string(d)
		at := strings.LastIndexByte(s, '@')
		if at < 0 {
			r.skip(p.name, "ss", "invalid legacy body")
			return
		}
		m, pw, ok := strings.Cut(s[:at], ":")
		if !ok {
			r.skip(p.name, "ss", "invalid legacy body")
			return
		}
		method, password, hp = m, pw, s[at+1:]
	}
	if pl := q.Get("plugin"); pl != "" {
		name, _, _ := strings.Cut(pl, ";")
		r.skip(p.name, "ss", "unsupported shadowsocks plugin "+name)
		return
	}
	h, pt, ok := splitHostPort(hp)
	if !ok {
		r.skip(p.name, "ss", "invalid host or port")
		return
	}
	o := outbound.Options{Name: p.name, Type: "shadowsocks", Server: h, Port: pt, Method: strings.ToLower(method)}
	if strings.HasPrefix(o.Method, "2022-") {
		o.Key = password
	} else {
		o.Password = password
	}
	r.add(Node{Options: o}, "ss")
}

func uriTLS(r *Result, p uriParts, q url.Values) {
	typ := p.scheme
	switch sec := strings.ToLower(q.Get("security")); sec {
	case "", "tls":
	case "reality":
		r.skip(p.name, typ, "REALITY is not supported")
		return
	default:
		r.skip(p.name, typ, "security="+sec+" is not supported (TLS required)")
		return
	}
	if t := strings.ToLower(q.Get("type")); t != "" && t != "tcp" {
		r.skip(p.name, typ, "unsupported transport "+t)
		return
	}
	h, pt, ok := splitHostPort(p.hostport)
	if !ok {
		r.skip(p.name, typ, "invalid host or port")
		return
	}
	t := &outbound.TLSOptions{ServerName: q.Get("sni"), Insecure: truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))}
	if t.ServerName == "" {
		t.ServerName = q.Get("peer")
	}
	if a := q.Get("alpn"); a != "" {
		for _, s := range strings.Split(a, ",") {
			if s = strings.TrimSpace(s); s != "" {
				t.ALPN = append(t.ALPN, s)
			}
		}
	}
	o := outbound.Options{Name: p.name, Type: typ, Server: h, Port: pt, Password: unescape(p.userinfo), TLS: t}
	r.add(Node{Options: o, ClientFingerprint: q.Get("fp")}, typ)
}

func uriSocks(r *Result, p uriParts) {
	h, pt, ok := splitHostPort(p.hostport)
	if !ok {
		r.skip(p.name, p.scheme, "invalid host or port")
		return
	}
	o := outbound.Options{Name: p.name, Type: "socks5", Server: h, Port: pt}
	if p.hasAt && p.userinfo != "" {
		u, pw, ok := strings.Cut(p.userinfo, ":")
		if ok {
			o.Username, o.Password = unescape(u), unescape(pw)
		} else if d, ok := decodeBase64(unescape(p.userinfo)); ok {
			u, pw, ok := strings.Cut(string(d), ":")
			if !ok {
				r.skip(p.name, p.scheme, "invalid userinfo")
				return
			}
			o.Username, o.Password = u, pw
		} else {
			r.skip(p.name, p.scheme, "invalid userinfo")
			return
		}
	}
	r.add(Node{Options: o}, p.scheme)
}
