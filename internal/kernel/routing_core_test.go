package kernel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
)

// ---- configuration: strict schema and graph validation ----

func loadJSON(t *testing.T, body string) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if e := os.WriteFile(p, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := Load(p)
	return e
}

const rcInbound = `"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}]`
const rcKey = "QUFBQUFBQUFBQUFBQUFBQQ=="

func rcOut(name, extra string) string {
	return `{"name":"` + name + `","type":"shadowsocks","server":"127.0.0.1","port":8388,"method":"2022-blake3-aes-128-gcm","key":"` + rcKey + `"` + extra + `}`
}

func TestRoutingCoreConfigSchema(t *testing.T) {
	dir := t.TempDir()
	full := `{` + rcInbound + `,
	 "outbounds":[` + rcOut("hk", "") + `,
	   {"name":"jp","type":"anytls","server":"jp.example","port":443,"password":"p","tls":{"server_name":"jp.example"},"via":"hk"},
	   {"name":"us","type":"trojan","server":"203.0.113.9","port":443,"password":"p","tls":{},"udp":false},
	   {"name":"s5","type":"socks5","server":"127.0.0.1","port":1080,"username":"u","password":"p"}],
	 "groups":[{"name":"pick","type":"select","members":["jp","us","direct","reject"],"selected":"us"},
	   {"name":"auto","type":"url-test","members":["jp","us"],"probe":{"url":"http://127.0.0.1:9/","interval":"10m","timeout":"5s"},"tolerance":"50ms"},
	   {"name":"fb","type":"fallback","members":["auto","s5"],"probe":{"url":"https://127.0.0.1:9/"}},
	   {"name":"sm","type":"smart","members":["hk","jp"],"probe":{"url":"http://127.0.0.1:9/"},"priority":{"hk":1.5}}],
	 "rule_sets":[{"name":"ads","format":"domain","path":"` + dir + `/ads.txt"},{"name":"ips","format":"ipcidr","path":"` + dir + `/ips.txt","url":"https://127.0.0.1:9/ips.txt","interval":"1h","via":"fb"}],
	 "geoip":{"path":"` + dir + `/c.mmdb"},
	 "routing":{"rules":[{"rule_set":"ads","action":"reject"},{"domain_suffix":"openai.com","outbound":"sm"},{"geoip":"CN","action":"direct"},
	   {"ip_cidr":"10.0.0.0/8","action":"reject","no_resolve":true},{"src_ip_cidr":"192.168.0.0/16","outbound":"pick"},{"dst_port":"1000-2000","outbound":"direct"},
	   {"network":"udp","outbound":"jp"},{"domain_keyword":"tube","outbound":"reject"},{"domain":"x.example","outbound":"auto"},{"rule_set":"ips","outbound":"fb"}],"final":"pick"}}`
	if e := loadJSON(t, full); e != nil {
		t.Fatal("full config rejected:", e)
	}
	legacy := `{` + rcInbound + `,"dns":{"server":"udp://127.0.0.1:53"},"routing":{"rules":[{"domain":"a.example","action":"reject"},{"domain_suffix":"b.example","action":"direct"},{"ip_cidr":"10.0.0.0/8","action":"reject"}]}}`
	if e := loadJSON(t, legacy); e != nil {
		t.Fatal("legacy routing rejected:", e)
	}
	bad := map[string]string{
		"unknown outbound field":   `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"bogus":1`) + `]}`,
		"unknown nested tls field": `{` + rcInbound + `,"outbounds":[{"name":"a","type":"trojan","server":"127.0.0.1","port":1,"password":"p","tls":{"bogus":true}}]}`,
		"null tls":                 `{` + rcInbound + `,"outbounds":[{"name":"a","type":"trojan","server":"127.0.0.1","port":1,"password":"p","tls":null}]}`,
		"null outbounds":           `{` + rcInbound + `,"outbounds":null}`,
		"null groups":              `{` + rcInbound + `,"groups":null}`,
		"null rule_sets":           `{` + rcInbound + `,"rule_sets":null}`,
		"null geoip":               `{` + rcInbound + `,"geoip":null}`,
		"null array element":       `{` + rcInbound + `,"outbounds":[null]}`,
		"empty via":                `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"via":""`) + `]}`,
		"null probe":               `{` + rcInbound + `,"outbounds":[` + rcOut("a", "") + `],"groups":[{"name":"g","type":"url-test","members":["a"],"probe":null}]}`,
		"unknown group field":      `{` + rcInbound + `,"outbounds":[` + rcOut("a", "") + `],"groups":[{"name":"g","type":"select","members":["a"],"x":1}]}`,
		"unknown rule_set field":   `{` + rcInbound + `,"rule_sets":[{"name":"r","format":"domain","path":"/x","y":1}]}`,
		"unknown geoip field":      `{` + rcInbound + `,"geoip":{"path":"/x","z":1}}`,
		"empty match string":       `{` + rcInbound + `,"routing":{"rules":[{"domain_keyword":"","action":"reject"}]}}`,
		"empty legacy match":       `{` + rcInbound + `,"routing":{"rules":[{"domain":"","action":"reject"}]}}`,
		"null match":               `{` + rcInbound + `,"routing":{"rules":[{"network":null,"action":"reject"}]}}`,
		"two matches":              `{` + rcInbound + `,"routing":{"rules":[{"network":"tcp","dst_port":"80","action":"reject"}]}}`,
		"action and outbound":      `{` + rcInbound + `,"outbounds":[` + rcOut("a", "") + `],"routing":{"rules":[{"network":"tcp","action":"reject","outbound":"a"}]}}`,
		"empty outbound":           `{` + rcInbound + `,"routing":{"rules":[{"network":"tcp","outbound":""}]}}`,
		"empty final":              `{` + rcInbound + `,"routing":{"final":""}}`,
		"null final":               `{` + rcInbound + `,"routing":{"final":null}}`,
		"unknown final":            `{` + rcInbound + `,"routing":{"final":"nope"}}`,
		"unknown rule outbound":    `{` + rcInbound + `,"routing":{"rules":[{"network":"udp","outbound":"nope"}]}}`,
		"unknown rule_set via":     `{` + rcInbound + `,"rule_sets":[{"name":"r","format":"domain","path":"/x","url":"https://127.0.0.1/r","via":"nope"}]}`,
		"unknown via":              `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"via":"nope"`) + `]}`,
		"via reject":               `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"via":"reject"`) + `]}`,
		"unknown member":           `{` + rcInbound + `,"groups":[{"name":"g","type":"select","members":["nope"]}]}`,
		"reserved name direct":     `{` + rcInbound + `,"outbounds":[` + rcOut("direct", "") + `]}`,
		"reserved group reject":    `{` + rcInbound + `,"groups":[{"name":"reject","type":"select","members":["direct"]}]}`,
		"duplicate name":           `{` + rcInbound + `,"outbounds":[` + rcOut("a", "") + `],"groups":[{"name":"a","type":"select","members":["direct"]}]}`,
		"name with space":          `{` + rcInbound + `,"outbounds":[` + rcOut("a b", "") + `]}`,
		"via cycle":                `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"via":"b"`) + `,` + rcOut("b", `,"via":"a"`) + `]}`,
		"self via":                 `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"via":"a"`) + `]}`,
		"group/via cycle":          `{` + rcInbound + `,"outbounds":[` + rcOut("a", `,"via":"g"`) + `],"groups":[{"name":"g","type":"select","members":["a","direct"]}]}`,
		"group cycle":              `{` + rcInbound + `,"groups":[{"name":"g","type":"select","members":["h"]},{"name":"h","type":"select","members":["g"]}]}`,
		"chain depth 5": `{` + rcInbound + `,"outbounds":[` + rcOut("a1", "") + `,` + rcOut("a2", `,"via":"a1"`) + `,` + rcOut("a3", `,"via":"a2"`) + `,` +
			rcOut("a4", `,"via":"g"`) + `,` + rcOut("a5", `,"via":"a4"`) + `],"groups":[{"name":"g","type":"select","members":["a3","direct"]}]}`,
		"bad protocol options": `{` + rcInbound + `,"outbounds":[{"name":"a","type":"shadowsocks","server":"127.0.0.1","port":1,"method":"2022-blake3-aes-128-gcm","key":"short"}]}`,
		"unsupported type":     `{` + rcInbound + `,"outbounds":[{"name":"a","type":"vless","server":"127.0.0.1","port":1}]}`,
		"geoip rule w/o db":    `{` + rcInbound + `,"routing":{"rules":[{"geoip":"CN","action":"direct"}]}}`,
		"auto group reject":    `{` + rcInbound + `,"groups":[{"name":"g","type":"fallback","members":["direct","reject"],"probe":{"url":"http://127.0.0.1/"}}]}`,
	}
	for name, body := range bad {
		if e := loadJSON(t, body); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Depth exactly 4 (a4 via a group whose member is 3 hops deep) is accepted.
	ok4 := `{` + rcInbound + `,"outbounds":[` + rcOut("a1", "") + `,` + rcOut("a2", `,"via":"a1"`) + `,` + rcOut("a3", `,"via":"a2"`) + `,` +
		rcOut("a4", `,"via":"g"`) + `],"groups":[{"name":"g","type":"select","members":["a3","direct"]}]}`
	if e := loadJSON(t, ok4); e != nil {
		t.Fatal("depth 4 rejected:", e)
	}
	// Bounds: 256 outbounds ok, 257 rejected; 64 groups ok, 65 rejected.
	many := func(n int) string {
		var parts []string
		for i := range n {
			parts = append(parts, rcOut(fmt.Sprintf("o%d", i), ""))
		}
		return `{` + rcInbound + `,"outbounds":[` + strings.Join(parts, ",") + `]}`
	}
	if e := loadJSON(t, many(256)); e != nil {
		t.Fatal("256 outbounds rejected:", e)
	}
	if e := loadJSON(t, many(257)); e == nil {
		t.Fatal("257 outbounds accepted")
	}
	groups := func(n int) string {
		var parts []string
		for i := range n {
			parts = append(parts, fmt.Sprintf(`{"name":"g%d","type":"select","members":["direct"]}`, i))
		}
		return `{` + rcInbound + `,"groups":[` + strings.Join(parts, ",") + `]}`
	}
	if e := loadJSON(t, groups(64)); e != nil {
		t.Fatal("64 groups rejected:", e)
	}
	if e := loadJSON(t, groups(65)); e == nil {
		t.Fatal("65 groups accepted")
	}
}

// The default configuration (no routing blocks) keeps the original fast path.
func TestRoutingCoreDefaultIsNoPolicy(t *testing.T) {
	s := startTest(t, Inbound{Protocol: "socks5"}, nil)
	if s.networkPolicy() || s.rt == nil || len(s.rt.outbounds) != 0 || len(s.rt.groups) != 0 {
		t.Fatal("default configuration must not enable a network policy")
	}
	s2 := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) { c.Routing = &RoutingOptions{Final: "reject"} })
	if !s2.networkPolicy() {
		t.Fatal("final reject must enable the policy path")
	}
	c, e := s2.dial(context.Background(), Address{"127.0.0.1", 9})
	if e == nil {
		c.Close()
		t.Fatal("final reject dialed")
	}
}

// ---- in-process forwarding through a real (in-process) upstream Kat ----

func rcEchoTCP(t *testing.T) uint16 {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(c, c)
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}
func rcEchoUDP(t *testing.T) uint16 {
	t.Helper()
	c := localUDP(t)
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			c.WriteTo(b[:n], a)
		}
	}()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}
func rcDNS(t *testing.T) *dnsFixture {
	return newDNSFixture(t, func(w []byte) []byte {
		var m dnsmessage.Message
		if m.Unpack(w) != nil || len(m.Questions) != 1 {
			return nil
		}
		if strings.HasSuffix(m.Questions[0].Name.String(), ".test.") {
			return dnsReply(w, []string{"127.0.0.1"}, 30)
		}
		return dnsReply(w, nil, 30)
	})
}
func rcTCPEcho(d outbound.Dialer, dst outbound.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := d.DialTCP(ctx, dst)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	p := make([]byte, 3000)
	rand.Read(p)
	if _, e = c.Write(p); e != nil {
		return e
	}
	got := make([]byte, len(p))
	if _, e = io.ReadFull(c, got); e != nil {
		return e
	}
	if !bytes.Equal(got, p) {
		return errors.New("echo mismatch")
	}
	return nil
}
func rcUDPEcho(pc outbound.PacketConn, dst outbound.Addr) error {
	p := make([]byte, 700)
	rand.Read(p)
	b := make([]byte, 65535)
	for range 5 {
		if _, e := pc.WriteTo(p, dst); e != nil {
			return e
		}
		pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, e := pc.ReadFrom(b)
		if e == nil && bytes.Equal(b[:n], p) {
			return nil
		}
	}
	return errors.New("no UDP echo")
}

func TestRoutingCoreInProcessProxy(t *testing.T) {
	dns := rcDNS(t)
	echo, uecho := rcEchoTCP(t), rcEchoUDP(t)
	before := runtime.NumGoroutine()
	var upLog, entryLog bytes.Buffer
	var logMu sync.Mutex
	sink := func(b *bytes.Buffer) func([]byte) error {
		return func(p []byte) error { logMu.Lock(); defer logMu.Unlock(); _, e := b.Write(p); return e }
	}
	upCfg := Config{DNS: &DNSOptions{Server: "udp://" + dns.udp.LocalAddr().String()}, UDPBindIPv4: "127.0.0.1", Inbounds: []Inbound{{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: ssIn().SS}},
		Limits: Limits{HandshakeTimeout: Duration(2 * time.Second), DialTimeout: Duration(2 * time.Second), DrainTimeout: Duration(time.Second), UDPIdle: Duration(2 * time.Second)}}
	up, e := Start(upCfg)
	if e != nil {
		t.Fatal(e)
	}
	up.failures.write = sink(&upLog)
	upPort := uint16(up.Addresses()[0].(*net.TCPAddr).Port)
	key := base64.StdEncoding.EncodeToString(key2022())
	f := false
	entryCfg := Config{DNS: &DNSOptions{Server: "udp://" + dns.udp.LocalAddr().String()}, UDPBindIPv4: "127.0.0.1",
		Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}},
		Outbounds: []OutboundConfig{
			{Name: "up", Type: "shadowsocks", Server: "127.0.0.1", Port: upPort, Method: "2022-blake3-aes-128-gcm", Key: key},
			{Name: "up-tcp", Type: "shadowsocks", Server: "127.0.0.1", Port: upPort, Method: "2022-blake3-aes-128-gcm", Key: key, UDP: &f},
		},
		Groups: []GroupConfig{{Name: "sel", Type: "select", Members: []string{"up", "direct", "reject"}, Selected: "up"},
			{Name: "blocked", Type: "select", Members: []string{"reject", "up"}}},
		Routing: &RoutingOptions{Rules: []RouteRule{
			{DomainSuffix: "proxy.test", Outbound: "sel"},
			{DomainSuffix: "rejectgroup.test", Outbound: "blocked"},
			{DomainSuffix: "tcponly.test", Outbound: "up-tcp"},
			{SrcIPCIDR: "10.0.0.0/8", Action: "reject"},
			{Network: "udp", Outbound: "up"},
			{DomainKeyword: "nope", Action: "reject"},
		}, Final: "direct"},
		Limits: Limits{HandshakeTimeout: Duration(2 * time.Second), DialTimeout: Duration(2 * time.Second), DrainTimeout: Duration(time.Second), UDPIdle: Duration(time.Second)}}
	entry, e := Start(entryCfg)
	if e != nil {
		up.Close(context.Background())
		t.Fatal(e)
	}
	entry.failures.write = sink(&entryLog)
	entry.events.write = sink(&entryLog)
	client, e := socks5.New(outbound.Options{Name: "c", Type: "socks5", Server: "127.0.0.1", Port: uint16(entry.Addresses()[0].(*net.TCPAddr).Port)}, direct.New(direct.Options{}))
	if e != nil {
		t.Fatal(e)
	}
	accepted := func() int64 { return up.Stats().Accepted }
	// TCP: domain rule -> select group -> SS outbound -> upstream Kat -> echo.
	a0 := accepted()
	if e := rcTCPEcho(client, outbound.Addr{Host: "a.proxy.test", Port: echo}); e != nil {
		t.Fatal("proxied TCP:", e)
	}
	if accepted() != a0+1 {
		t.Fatal("proxied TCP did not traverse the upstream", accepted()-a0)
	}
	// TCP: final direct (src 127.0.0.1 is not in 10/8) -> no upstream use.
	a0 = accepted()
	if e := rcTCPEcho(client, outbound.Addr{Host: "127.0.0.1", Port: echo}); e != nil || accepted() != a0 {
		t.Fatal("direct TCP:", e, accepted()-a0)
	}
	// TCP: select group whose selection is the built-in reject.
	if e := rcTCPEcho(client, outbound.Addr{Host: "x.rejectgroup.test", Port: echo}); e == nil {
		t.Fatal("reject member dialed")
	}
	// UDP: network rule -> SS native UDP through the upstream.
	pc, e := client.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e := rcUDPEcho(pc, outbound.Addr{Host: "127.0.0.1", Port: uecho}); e != nil {
		t.Fatal("proxied UDP:", e)
	}
	if up.Stats().UDP != 1 {
		t.Fatal("UDP did not reach the upstream association", up.Stats().UDP)
	}
	// UDP to an outbound that disables UDP is dropped and reported.
	if e := rcUDPEcho(pc, outbound.Addr{Host: "u.tcponly.test", Port: uecho}); e == nil {
		t.Fatal("UDP through a TCP-only outbound echoed")
	} else {
		t.Log("TCP-only outbound UDP:", e)
	}
	// After udp_idle (1s) without traffic the association (and with it every
	// proxy session and reader) ends; a new association proxies again.
	deadline := time.Now().Add(4 * time.Second)
	for entry.counters.UDP.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if entry.counters.UDP.Load() != 0 {
		t.Fatal("idle UDP association with proxy session was not recycled")
	}
	pc.Close()
	pc, e = client.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e := rcUDPEcho(pc, outbound.Addr{Host: "v.proxy.test", Port: uecho}); e != nil {
		t.Fatal("proxied UDP (domain, second association):", e)
	}
	pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := entry.Close(ctx); e != nil {
		t.Fatal("entry close:", e)
	}
	if e := up.Close(ctx); e != nil {
		t.Fatal("upstream close:", e)
	}
	logMu.Lock()
	out := entryLog.String()
	logMu.Unlock()
	for _, want := range []string{"reason=udp_unsupported", "reason=rule_reject"} {
		if !strings.Contains(out, want) {
			t.Fatalf("entry log lacks %s:\n%s", want, out)
		}
	}
	for _, secret := range []string{"proxy.test", "127.0.0.1", key} {
		if strings.Contains(out, secret) {
			t.Fatalf("entry log leaked %q:\n%s", secret, out)
		}
	}
	// No goroutine survives Close of both servers (outbounds, groups, engine,
	// UDP proxy sessions and their readers included).
	deadline = time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<20)
		t.Fatalf("goroutines %d > %d after Close:\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

func TestRoutingCoreSourceCIDR(t *testing.T) {
	echo := rcEchoTCP(t)
	s := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) {
		c.Routing = &RoutingOptions{Rules: []RouteRule{{SrcIPCIDR: "127.0.0.0/8", Action: "reject"}}}
	})
	client, _ := socks5.New(outbound.Options{Name: "c", Type: "socks5", Server: "127.0.0.1", Port: uint16(s.Addresses()[0].(*net.TCPAddr).Port)}, direct.New(direct.Options{}))
	if e := rcTCPEcho(client, outbound.Addr{Host: "127.0.0.1", Port: echo}); e == nil {
		t.Fatal("src_ip_cidr reject ignored")
	}
	s2 := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) {
		c.Routing = &RoutingOptions{Rules: []RouteRule{{SrcIPCIDR: "10.0.0.0/8", Action: "reject"}}}
	})
	client2, _ := socks5.New(outbound.Options{Name: "c", Type: "socks5", Server: "127.0.0.1", Port: uint16(s2.Addresses()[0].(*net.TCPAddr).Port)}, direct.New(direct.Options{}))
	if e := rcTCPEcho(client2, outbound.Addr{Host: "127.0.0.1", Port: echo}); e != nil {
		t.Fatal("non-matching src_ip_cidr rejected:", e)
	}
}

func TestRoutingCoreEventLog(t *testing.T) {
	var b bytes.Buffer
	l := &eventLog{write: func(p []byte) error { _, e := b.Write(p); return e }}
	now := time.Unix(100, 0)
	for range 30 {
		l.emit(now, "group_switch", "group", "g x=1\nevil", "from", "a", "to", "b")
	}
	l.emit(now, "secret-event", "dst", "203.0.113.1")
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != eventBurst+1 {
		t.Fatal("event rate limit", len(lines))
	}
	if lines[0] != "kat event=group_switch group=g_x_1_evil from=a to=b suppressed=0" {
		t.Fatal("event shape", lines[0])
	}
	if lines[len(lines)-1] != "kat event=other suppressed=0" || strings.Contains(b.String(), "203.0.113.1") {
		t.Fatal("unknown event leaked fields", lines[len(lines)-1])
	}
	b.Reset()
	l.emit(now.Add(eventWindow), "group_switch", "group", "g")
	if !strings.Contains(b.String(), "suppressed=20") {
		t.Fatal("suppressed count", b.String())
	}
	l.shutdown()
	b.Reset()
	l.emit(now.Add(2*eventWindow), "group_switch")
	if b.Len() != 0 {
		t.Fatal("event after shutdown")
	}
}
