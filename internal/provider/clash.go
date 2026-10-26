package provider

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shui1iao/Kat/internal/outbound"
)

func isClash(b []byte) bool {
	var doc map[string]any
	if yaml.Unmarshal(b, &doc) != nil {
		return false
	}
	_, ok := doc["proxies"]
	return ok
}

func parseClash(b []byte) (Result, error) {
	var doc struct {
		Proxies []any `yaml:"proxies"`
	}
	if e := yaml.Unmarshal(b, &doc); e != nil {
		return Result{}, fmt.Errorf("%w: invalid YAML", ErrFormat)
	}
	if doc.Proxies == nil {
		return Result{}, fmt.Errorf("%w: no proxies list", ErrFormat)
	}
	r := Result{Format: FormatClash}
	for _, item := range doc.Proxies {
		m, ok := item.(map[string]any)
		if !ok {
			r.skip("", "", "entry is not a mapping")
			continue
		}
		clashNode(&r, m)
	}
	return r, nil
}

// field helpers for decoded YAML/JSON maps

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func flag(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(strings.TrimSpace(v))
		return b
	case int:
		return v != 0
	case float64:
		return v != 0
	}
	return false
}

func has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func sub(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

func strList(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		var out []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func port(s string) uint16 {
	n, e := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if e != nil {
		return 0
	}
	return uint16(n)
}

func host(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	return s
}

// clashIgnored are mihomo node fields that have no effect in Kat (local
// socket tuning or client-side options).
var clashIgnored = []string{"tfo", "mptcp", "ip-version", "interface-name", "routing-mark", "udp-over-tcp", "udp-over-tcp-version", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"}

func clashNode(r *Result, m map[string]any) {
	name := str(m, "name")
	typ := strings.ToLower(str(m, "type"))
	if dp := str(m, "dialer-proxy"); dp != "" {
		r.skip(name, typ, "dialer-proxy chaining is not supported in providers")
		return
	}
	if s := sub(m, "smux"); s != nil && flag(s, "enabled") {
		r.skip(name, typ, "smux multiplexing is not supported")
		return
	}
	o := outbound.Options{Name: name, Server: host(str(m, "server")), Port: port(str(m, "port")), UDP: boolPtr(flag(m, "udp"))}
	n := Node{}
	switch typ {
	case "ss":
		if p := str(m, "plugin"); p != "" {
			r.skip(name, typ, "unsupported shadowsocks plugin "+p)
			return
		}
		o.Type, o.Method = "shadowsocks", strings.ToLower(str(m, "cipher"))
		if strings.HasPrefix(o.Method, "2022-") {
			o.Key = str(m, "password")
		} else {
			o.Password = str(m, "password")
		}
	case "trojan":
		if nw := strings.ToLower(str(m, "network")); nw != "" && nw != "tcp" {
			r.skip(name, typ, "unsupported transport "+nw)
			return
		}
		if has(m, "reality-opts") {
			r.skip(name, typ, "REALITY is not supported")
			return
		}
		if s := sub(m, "ss-opts"); s != nil && flag(s, "enabled") {
			r.skip(name, typ, "trojan-go shadowsocks layer is not supported")
			return
		}
		o.Type, o.Password = "trojan", str(m, "password")
		o.TLS = clashTLS(m)
	case "anytls":
		if nw := strings.ToLower(str(m, "network")); nw != "" && nw != "tcp" {
			r.skip(name, typ, "unsupported transport "+nw)
			return
		}
		if has(m, "reality-opts") {
			r.skip(name, typ, "REALITY is not supported")
			return
		}
		o.Type, o.Password = "anytls", str(m, "password")
		o.TLS = clashTLS(m)
	case "socks5":
		if flag(m, "tls") {
			r.skip(name, typ, "SOCKS5 over TLS is not supported")
			return
		}
		o.Type, o.Username, o.Password = "socks5", str(m, "username"), str(m, "password")
	case "":
		r.skip(name, typ, "missing type")
		return
	default:
		r.skip(name, typ, "unsupported type "+typ)
		return
	}
	n.ClientFingerprint = str(m, "client-fingerprint")
	if n.ClientFingerprint != "" && o.Type != "trojan" && o.Type != "anytls" {
		n.Ignored = append(n.Ignored, "client-fingerprint")
	}
	for _, k := range clashIgnored {
		if has(m, k) {
			n.Ignored = append(n.Ignored, k)
		}
	}
	sort.Strings(n.Ignored)
	n.Options = o
	r.add(n, typ)
}

func clashTLS(m map[string]any) *outbound.TLSOptions {
	t := &outbound.TLSOptions{ServerName: str(m, "sni"), Insecure: flag(m, "skip-cert-verify"), ALPN: strList(m, "alpn")}
	if t.ServerName == "" {
		t.ServerName = str(m, "servername")
	}
	// mihomo "fingerprint" is the SHA-256 certificate pin.
	if fp := str(m, "fingerprint"); fp != "" {
		t.PinSHA256 = fp
		t.Insecure = false
	}
	return t
}
