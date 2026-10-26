package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/shui1iao/Kat/internal/outbound"
)

// sing-box outbound types that are not proxy nodes.
var singBoxNonNode = map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}

func parseSingBox(b []byte) (Result, error) {
	var list []any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var top any
	if e := d.Decode(&top); e != nil {
		return Result{}, fmt.Errorf("%w: invalid JSON", ErrFormat)
	}
	if d.Decode(new(any)) != io.EOF {
		return Result{}, fmt.Errorf("%w: trailing JSON data", ErrFormat)
	}
	switch v := top.(type) {
	case map[string]any:
		ob, ok := v["outbounds"].([]any)
		if !ok {
			return Result{}, fmt.Errorf("%w: no outbounds array", ErrFormat)
		}
		list = ob
		if ep, ok := v["endpoints"].([]any); ok {
			list = append(list, ep...)
		}
	case []any:
		list = v
	default:
		return Result{}, ErrFormat
	}
	r := Result{Format: FormatSingBox}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			r.skip("", "", "entry is not an object")
			continue
		}
		singBoxNode(&r, m)
	}
	return r, nil
}

func jsonStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

func jsonBool(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

func singBoxNode(r *Result, m map[string]any) {
	name, typ := jsonStr(m, "tag"), strings.ToLower(jsonStr(m, "type"))
	if singBoxNonNode[typ] {
		r.skip(name, typ, "not a proxy node (sing-box "+typ+")")
		return
	}
	if jsonStr(m, "detour") != "" {
		r.skip(name, typ, "detour chaining is not supported in providers")
		return
	}
	if mx, _ := m["multiplex"].(map[string]any); mx != nil && jsonBool(mx, "enabled") {
		r.skip(name, typ, "multiplex is not supported")
		return
	}
	if tr, _ := m["transport"].(map[string]any); tr != nil {
		r.skip(name, typ, "unsupported transport "+jsonStr(tr, "type"))
		return
	}
	nw := strings.ToLower(jsonStr(m, "network"))
	o := outbound.Options{Name: name, Server: host(jsonStr(m, "server")), Port: port(jsonStr(m, "server_port")), UDP: boolPtr(nw != "tcp")}
	n := Node{}
	switch typ {
	case "shadowsocks":
		if p := jsonStr(m, "plugin"); p != "" {
			r.skip(name, typ, "unsupported shadowsocks plugin "+p)
			return
		}
		o.Type, o.Method = "shadowsocks", strings.ToLower(jsonStr(m, "method"))
		if strings.HasPrefix(o.Method, "2022-") {
			o.Key = jsonStr(m, "password")
		} else {
			o.Password = jsonStr(m, "password")
		}
		if _, ok := m["udp_over_tcp"]; ok {
			n.Ignored = append(n.Ignored, "udp_over_tcp")
		}
	case "trojan", "anytls":
		t, fp, reason := singBoxTLS(m)
		if reason != "" {
			r.skip(name, typ, reason)
			return
		}
		o.Type, o.Password, o.TLS, n.ClientFingerprint = typ, jsonStr(m, "password"), t, fp
		for _, k := range []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"} {
			if _, ok := m[k]; ok {
				n.Ignored = append(n.Ignored, k)
			}
		}
	case "socks":
		if t := sub(m, "tls"); t != nil && jsonBool(t, "enabled") {
			r.skip(name, typ, "SOCKS5 over TLS is not supported")
			return
		}
		if v := jsonStr(m, "version"); v != "" && v != "5" {
			r.skip(name, typ, "SOCKS version "+v+" is not supported")
			return
		}
		o.Type, o.Username, o.Password = "socks5", jsonStr(m, "username"), jsonStr(m, "password")
		if _, ok := m["udp_over_tcp"]; ok {
			n.Ignored = append(n.Ignored, "udp_over_tcp")
		}
	case "":
		r.skip(name, typ, "missing type")
		return
	default:
		r.skip(name, typ, "unsupported type "+typ)
		return
	}
	for _, k := range []string{"tcp_fast_open", "tcp_multi_path", "bind_interface", "routing_mark", "domain_resolver", "connect_timeout"} {
		if has(m, k) {
			n.Ignored = append(n.Ignored, k)
		}
	}
	n.Options = o
	r.add(n, typ)
}

// singBoxTLS maps the tls object; reason is non-empty when the node must be skipped.
func singBoxTLS(m map[string]any) (*outbound.TLSOptions, string, string) {
	t, _ := m["tls"].(map[string]any)
	if t == nil || !jsonBool(t, "enabled") {
		return nil, "", "TLS is required"
	}
	if rl, _ := t["reality"].(map[string]any); rl != nil && jsonBool(rl, "enabled") {
		return nil, "", "REALITY is not supported"
	}
	if ech, _ := t["ech"].(map[string]any); ech != nil && jsonBool(ech, "enabled") {
		return nil, "", "ECH is not supported"
	}
	if _, ok := t["certificate"]; ok {
		return nil, "", "inline tls.certificate is not supported"
	}
	o := &outbound.TLSOptions{ServerName: jsonStr(t, "server_name"), Insecure: jsonBool(t, "insecure")}
	switch a := t["alpn"].(type) {
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s != "" {
				o.ALPN = append(o.ALPN, s)
			}
		}
	case string:
		if a != "" {
			o.ALPN = []string{a}
		}
	}
	fp := ""
	if u, _ := t["utls"].(map[string]any); u != nil && jsonBool(u, "enabled") {
		fp = jsonStr(u, "fingerprint")
		if fp == "" {
			fp = "chrome" // sing-box default when utls is enabled
		}
	}
	return o, fp, ""
}
