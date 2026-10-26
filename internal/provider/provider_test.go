package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestManagerActualExportsFieldByField(t *testing.T) {
	var rows []struct {
		Kind, Host, URI string
		Input           struct {
			Port                                    uint16
			Password, Method, Policy, SNI, Username string
		}
		Mihomo map[string]any
	}
	b, e := os.ReadFile("testdata/manager-display.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	for i, row := range rows {
		typ := row.Kind
		if typ == "ss" {
			typ = "shadowsocks"
		}
		want := outbound.Options{Name: "VPS", Type: typ, Server: row.Host, Port: row.Input.Port}
		switch typ {
		case "shadowsocks":
			want.Method = row.Input.Method
			if strings.HasPrefix(want.Method, "2022-") {
				want.Key = row.Input.Password
			} else {
				want.Password = row.Input.Password
			}
		case "socks5":
			want.Username = row.Input.Username
			want.Password = row.Input.Password
		default:
			want.Password = row.Input.Password
			want.TLS = &outbound.TLSOptions{ServerName: row.Input.SNI, Insecure: row.Input.Policy != "supplied"}
		}
		clash, _ := json.Marshal(map[string]any{"proxies": []any{row.Mihomo}})
		for _, data := range [][]byte{clash, []byte(row.URI)} {
			res, e := Parse(data, "")
			if e != nil || len(res.Nodes) != 1 {
				t.Fatalf("%d %s: %+v %v", i, data, res, e)
			}
			got := res.Nodes[0].Options
			if !got.UDPEnabled() {
				t.Fatal("Manager UDP flag lost")
			}
			got.UDP = nil
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("export %d fields: got %#v want %#v", i, got, want)
			}
		}
		t.Logf("real display export #%d kind=%s IPv6 Unicode user/password: every outbound field matched URI and Mihomo", i, row.Kind)
	}
}
func TestSingBoxFieldMappingAndSkips(t *testing.T) {
	data := `{"outbounds":[{"type":"shadowsocks","tag":"SS","server":"::1","server_port":1234,"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==","network":"tcp","udp_over_tcp":true},{"type":"trojan","tag":"TLS","server":"example.com","server_port":443,"password":"密码","tls":{"enabled":true,"server_name":"sni.example","insecure":true,"alpn":["h2","http/1.1"],"utls":{"enabled":true,"fingerprint":"chrome"}}},{"type":"socks","tag":"SOCKS","server":"::1","server_port":1080,"username":"用户","password":"秘密","version":"5"},{"type":"anytls","tag":"ANY","server":"::1","server_port":443,"password":"p","tls":{"enabled":true},"idle_session_timeout":"30s"},{"type":"socks","tag":"no-tls","server":"::1","server_port":443,"tls":{"enabled":true}},{"type":"trojan","tag":"no-reality","tls":{"enabled":true,"reality":{"enabled":true}}},{"type":"trojan","tag":"no-ech","tls":{"enabled":true,"ech":{"enabled":true}}},{"type":"trojan","tag":"no-cert","tls":{"enabled":true,"certificate":["x"]}},{"type":"shadowsocks","tag":"no-detour","detour":"x"},{"type":"anytls","tag":"no-mux","multiplex":{"enabled":true}},{"type":"trojan","tag":"no-ws","transport":{"type":"ws"}},{"type":"vless","tag":"unsupported"},{"type":"direct","tag":"direct"}]}`
	res, e := Parse([]byte(data), "")
	if e != nil {
		t.Fatal(e)
	}
	if len(res.Nodes) != 4 || len(res.Skipped) != 9 {
		t.Fatal(len(res.Nodes), res.Skipped)
	}
	want := []Node{
		{Options: outbound.Options{Name: "SS", Type: "shadowsocks", Server: "::1", Port: 1234, Method: "2022-blake3-aes-128-gcm", Key: "AAECAwQFBgcICQoLDA0ODw==", UDP: boolPtr(false)}, Ignored: []string{"udp_over_tcp"}},
		{Options: outbound.Options{Name: "TLS", Type: "trojan", Server: "example.com", Port: 443, Password: "密码", UDP: boolPtr(true), TLS: &outbound.TLSOptions{ServerName: "sni.example", Insecure: true, ALPN: []string{"h2", "http/1.1"}}}, ClientFingerprint: "chrome"},
		{Options: outbound.Options{Name: "SOCKS", Type: "socks5", Server: "::1", Port: 1080, Username: "用户", Password: "秘密", UDP: boolPtr(true)}},
		{Options: outbound.Options{Name: "ANY", Type: "anytls", Server: "::1", Port: 443, Password: "p", UDP: boolPtr(true), TLS: &outbound.TLSOptions{}}, Ignored: []string{"idle_session_timeout"}},
	}
	if !reflect.DeepEqual(res.Nodes, want) {
		for i, n := range res.Nodes {
			t.Logf("%d got=%#v want=%#v", i, n, want[i])
		}
		t.Fatal("field mismatch")
	}
	for _, s := range res.Skipped {
		if s.Reason == "" {
			t.Fatal(s)
		}
		t.Logf("skip %s: %s", s.Name, s.Reason)
	}
	if _, e := Parse([]byte(data+`{}`), FormatSingBox); e == nil {
		t.Fatal("trailing JSON accepted")
	}
}
func TestURIBase64NamesAndUnsupported(t *testing.T) {
	base := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:密码+:/@")) + "@[::1]:8388#香港%20%F0%9F%87%AD%F0%9F%87%B0"
	list := "# comment\n\n" + base + "\n" + base + "\n// comment\nss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p@127.0.0.1:1")) + "#legacy\n" + base + "?unused\n"
	// Keep query out of the fragment: explicit SIP002 plugin must be skipped.
	list = base + "\n" + base + "\nss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p@127.0.0.1:1")) + "#legacy\n" + strings.Split(base, "#")[0] + "?plugin=v2ray-plugin%3Bobfs%3Dwebsocket#plugin\nvless://x@127.0.0.1:1#vless\n# comment\n\n"
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for _, data := range []string{list, enc.EncodeToString([]byte(list))} {
			r, e := Parse([]byte(data), "")
			if e != nil || len(r.Nodes) != 3 || len(r.Skipped) != 2 || len(r.Renamed) != 1 {
				t.Fatal(r, e)
			}
			if r.Nodes[0].Options.Password != "密码+:/@" || r.Nodes[0].Options.Server != "::1" || r.Nodes[1].Options.Name != r.Nodes[0].Options.Name+"#2" {
				t.Fatal("URI mapping")
			}
		}
	}
	long := strings.Repeat("港", 42) + "ab"
	body := fmt.Sprintf("proxies:\n - {name: %s, type: socks5, server: \"::1\", port: 1}\n - {name: %s, type: socks5, server: \"::1\", port: 1}\n", long, long)
	r, e := Parse([]byte(body), "")
	if e != nil || len(r.Nodes) != 2 || len(r.Nodes[1].Options.Name) > MaxNameSize {
		t.Fatal(r, e)
	}
}
func TestClashDefaultsPinAndUnsupported(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	data := fmt.Sprintf(`proxies:
 - {name: TLS, type: trojan, server: 127.0.0.1, port: 443, password: p, sni: localhost, fingerprint: %s, skip-cert-verify: true, client-fingerprint: chrome, tfo: true}
 - {name: SS, type: ss, server: "::1", port: 1, cipher: aes-128-gcm, password: p}
 - {name: plugin, type: ss, plugin: obfs}
 - {name: ws, type: trojan, network: ws}
 - {name: reality, type: anytls, reality-opts: {public-key: x}}
 - {name: detour, type: socks5, dialer-proxy: x}
 - {name: mux, type: anytls, smux: {enabled: true}}
 - {name: tls-socks, type: socks5, tls: true}
 - {name: eih, type: ss, server: "::1", port: 1, cipher: 2022-blake3-aes-128-gcm, password: 'AAECAwQFBgcICQoLDA0ODw==:AAECAwQFBgcICQoLDA0ODw=='}
 - {name: vless, type: vless}
`, pin)
	r, e := Parse([]byte(data), "")
	if e != nil || len(r.Nodes) != 2 || len(r.Skipped) != 8 {
		t.Fatal(r, e)
	}
	n := r.Nodes[0]
	if n.Options.UDPEnabled() || n.Options.TLS.PinSHA256 != pin || n.Options.TLS.Insecure || n.ClientFingerprint != "chrome" || !reflect.DeepEqual(n.Ignored, []string{"tfo"}) {
		t.Fatal(n)
	}
	for _, v := range r.Skipped {
		t.Logf("%s %s", v.Name, v.Reason)
	}
}

func TestRealSingBoxFormattedExport(t *testing.T) {
	body, e := os.ReadFile("testdata/sing-box-formatted.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct{ URI string }
	b, e := os.ReadFile("testdata/manager-display.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	res, e := Parse(body, "")
	if e != nil || len(res.Nodes) != len(rows) || len(res.Skipped) != 0 {
		t.Fatal(res, e)
	}
	for i, row := range rows {
		uri, e := Parse([]byte(row.URI), "")
		if e != nil || len(uri.Nodes) != 1 {
			t.Fatal(uri, e)
		}
		want := uri.Nodes[0].Options
		want.Name = fmt.Sprintf("VPS-%d", i)
		want.UDP = boolPtr(true)
		if !reflect.DeepEqual(res.Nodes[i].Options, want) {
			t.Fatalf("field mismatch %d got=%#v want=%#v", i, res.Nodes[i].Options, want)
		}
	}
	t.Logf("sing-box 1.14.3 actual format/check export: %d nodes, all outbound fields equal verified Manager URI exports", len(rows))
}
