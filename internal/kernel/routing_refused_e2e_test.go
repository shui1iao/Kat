package kernel

// Real-process end-to-end tests for url-test's immediate re-test when the
// current member's proxy server refuses the TCP connection (its process was
// killed, the port is closed). Same gating and fixtures as
// routing_e2e_test.go (both KAT_E2E_KAT and KAT_INTEROP_SINGBOX must be set;
// otherwise the tests are skipped).
//
// The probe interval is 10m, so a re-test inside these tests can only come
// from a real connection failure. Every successful probe is one request to
// the shared HTTP probe server (w.httpCount); a probe through a refused
// member makes no request.

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type refGroup struct {
	proto, group, suffix string
	a, b                 string   // member names: a = current (fast), b = slower
	aProc, bProc         *e2eProc // a's own server (killed), b's server
}

// TestE2EURLTestServerRefused: the current member's server is killed; one
// connection meets the refusal, the group re-tests at once and switches.
func TestE2EURLTestServerRefused(t *testing.T) {
	w := e2eSetup(t)
	sbSocks := func(name string) *e2eProc { return w.singbox(name, 0, map[string]any{"type": "socks"}) }
	pin := map[string]any{"pin_sha256": w.pin}
	type proto struct {
		name, short string
		server      func(name string) *e2eProc
		out         func(name string, port int) map[string]any
	}
	protos := []proto{
		{"ss2022", "ss", func(n string) *e2eProc { return w.sbSS(n, 0) }, func(n string, p int) map[string]any {
			return map[string]any{"name": n, "type": "shadowsocks", "server": "127.0.0.1", "port": p, "method": e2eMethod, "key": e2eSBKey}
		}},
		{"trojan", "tj", w.sbTrojan, func(n string, p int) map[string]any {
			return map[string]any{"name": n, "type": "trojan", "server": "127.0.0.1", "port": p, "password": e2eTrojanPass, "tls": pin}
		}},
		{"anytls", "any", w.sbAnyTLS, func(n string, p int) map[string]any {
			return map[string]any{"name": n, "type": "anytls", "server": "127.0.0.1", "port": p, "password": e2eAnyTLSPass, "tls": pin}
		}},
		{"socks5", "sk", sbSocks, func(n string, p int) map[string]any {
			return map[string]any{"name": n, "type": "socks5", "server": "127.0.0.1", "port": p}
		}},
	}
	probe := map[string]any{"url": "http://127.0.0.1:" + strconv.Itoa(w.httpPort) + "/", "interval": "10m", "timeout": "2s"}
	var outs, groups, rules []any
	var cases []refGroup
	for _, p := range protos {
		ga := refGroup{proto: p.name, group: "gref_" + p.short, suffix: p.short + ".ref.e2e.test", a: p.short + "_a", b: p.short + "_b"}
		ga.aProc, ga.bProc = p.server("sb-"+p.short+"-a"), p.server("sb-"+p.short+"-b")
		// a connects straight to its server (killing it closes the port);
		// b goes through a forwarder that adds 150ms so a is the faster member.
		fb := w.forwarder(ga.b, ga.bProc.port, 150*time.Millisecond)
		outs = append(outs, p.out(ga.a, ga.aProc.port), p.out(ga.b, fb.port))
		groups = append(groups, map[string]any{"name": ga.group, "type": "url-test", "members": []any{ga.a, ga.b}, "probe": probe})
		rules = append(rules, map[string]any{"domain_suffix": ga.suffix, "outbound": ga.group})
		cases = append(cases, ga)
	}
	p, c := w.entry(map[string]any{
		"dns": map[string]any{"server": w.dnsServer()}, "outbounds": outs, "groups": groups,
		"routing": map[string]any{"rules": rules},
	})
	echo := w.echoTCP["127.0.0.1"]
	re := sbConn(echo)
	// Warm-up: first use starts each group's lazy probe round; a is chosen.
	for _, g := range cases {
		w.must(g.group+" warm-up", e2eTCP(c.socks, "warm."+g.suffix, echo))
	}
	time.Sleep(2500 * time.Millisecond)
	if n := p.countLines(regexp.MustCompile(`group_switch`)); n != 0 {
		t.Fatalf("switch before the kill:\n%s", p.text())
	}
	for _, g := range cases {
		na := g.aProc.countLines(re)
		w.must(g.group+" second warm-up", e2eTCP(c.socks, "warm2."+g.suffix, echo))
		if !g.aProc.waitLines(re, na+1, 3*time.Second) {
			t.Fatalf("%s: warm-up not served by %s", g.group, g.aProc.name)
		}
		w.logf("EVIDENCE %s: current member %s serves traffic (%s lines %d->%d)", g.group, g.a, g.aProc.name, na, g.aProc.countLines(re))
	}
	for _, g := range cases {
		g.aProc.kill()
		time.Sleep(300 * time.Millisecond)
		_, de := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(g.aProc.port), time.Second)
		if !errors.Is(de, syscall.ECONNREFUSED) {
			t.Fatalf("%s: port %d not refusing after kill: %v", g.group, g.aProc.port, de)
		}
		w.logf("PORT_CLOSED %s %s port=%d local dial: %v", g.group, g.aProc.name, g.aProc.port, de)
		sw := regexp.MustCompile(`kat event=group_switch group=` + g.group + ` from=` + g.a + ` to=` + g.b + `\b`)
		h0, nb := w.httpCount.Load(), g.bProc.countLines(re)
		t0 := time.Now()
		e := e2eTCP(c.socks, "c1."+g.suffix, echo)
		took := time.Since(t0)
		res := "ok"
		if e != nil {
			res = "FAIL(" + e.Error() + ")"
		}
		var toSwitch time.Duration
		for {
			if p.countLines(sw) > 0 {
				toSwitch = time.Since(t0)
				break
			}
			if time.Since(t0) > 5*time.Second {
				t.Fatalf("%s: no group_switch within 5s after one refused connection (http probes %d->%d):\n%s", g.group, h0, w.httpCount.Load(), p.text())
			}
			time.Sleep(5 * time.Millisecond)
		}
		h1 := w.httpCount.Load()
		bAfter1 := g.bProc.countLines(re)
		// after the switch: new connections go to b
		for i := 1; i <= 3; i++ {
			w.must(fmt.Sprintf("%s after switch %d", g.group, i), e2eTCP(c.socks, fmt.Sprintf("after%d.%s", i, g.suffix), echo))
		}
		if !g.bProc.waitLines(re, bAfter1+3, 3*time.Second) {
			t.Fatalf("%s: post-switch connections not served by %s", g.group, g.bProc.name)
		}
		w.logf("REFUSED_RESULT proto=%s group=%s killed=%s connections_before_switch=1 first_connection=%s first_connection_took=%s first_connection_served_by_%s=%d time_to_group_switch=%s probe_http_requests=%d->%d switch_event=%q post_switch_on_%s=%d->%d",
			g.proto, g.group, g.aProc.name, res, took.Round(time.Millisecond), g.bProc.name, bAfter1-nb, toSwitch.Round(time.Millisecond),
			h0, h1, sw.String(), g.bProc.name, bAfter1, g.bProc.countLines(re))
	}
	w.stopEntry(p)
}

// TestE2EURLTestRefusalNotImmediate: refusals that are not the member's own
// proxy server refusing keep the 3-failures-in-60s rule.
func TestE2EURLTestRefusalNotImmediate(t *testing.T) {
	w := e2eSetup(t)
	pin := map[string]any{"pin_sha256": w.pin}
	sbSSn := w.sbSS("sb-ss-n", 0)
	sbAny1, sbAny2 := w.sbAnyTLS("sb-anytls-n1"), w.sbAnyTLS("sb-anytls-n2")
	sbSk1 := w.singbox("sb-socks-n1", 0, map[string]any{"type": "socks"})
	sbSk2 := w.singbox("sb-socks-n2", 0, map[string]any{"type": "socks"})
	sbHop := w.singbox("sb-socks-hop", 0, map[string]any{"type": "socks"})
	sbTjC, sbTj2 := w.sbTrojan("sb-trojan-chain"), w.sbTrojan("sb-trojan-n2")
	fSS := w.forwarder("ss_n", sbSSn.port, 150*time.Millisecond)
	fAny2 := w.forwarder("any_n2", sbAny2.port, 150*time.Millisecond)
	fSk2 := w.forwarder("sk_n2", sbSk2.port, 150*time.Millisecond)
	fTj2 := w.forwarder("tj_n2", sbTj2.port, 150*time.Millisecond)
	probe := map[string]any{"url": "http://127.0.0.1:" + strconv.Itoa(w.httpPort) + "/", "interval": "10m", "timeout": "2s"}
	grp := func(name string, members ...any) map[string]any {
		return map[string]any{"name": name, "type": "url-test", "members": members, "probe": probe}
	}
	p, c := w.entry(map[string]any{
		"dns": map[string]any{"server": w.dnsServer()},
		"outbounds": []any{
			map[string]any{"name": "ss_n", "type": "shadowsocks", "server": "127.0.0.1", "port": fSS.port, "method": e2eMethod, "key": e2eSBKey},
			map[string]any{"name": "any_n1", "type": "anytls", "server": "127.0.0.1", "port": sbAny1.port, "password": e2eAnyTLSPass, "tls": pin},
			map[string]any{"name": "any_n2", "type": "anytls", "server": "127.0.0.1", "port": fAny2.port, "password": e2eAnyTLSPass, "tls": pin},
			map[string]any{"name": "sk_n1", "type": "socks5", "server": "127.0.0.1", "port": sbSk1.port},
			map[string]any{"name": "sk_n2", "type": "socks5", "server": "127.0.0.1", "port": fSk2.port},
			map[string]any{"name": "sk_hop", "type": "socks5", "server": "127.0.0.1", "port": sbHop.port},
			map[string]any{"name": "tj_via", "type": "trojan", "server": "127.0.0.1", "port": sbTjC.port, "password": e2eTrojanPass, "tls": pin, "via": "sk_hop"},
			map[string]any{"name": "tj_n2", "type": "trojan", "server": "127.0.0.1", "port": fTj2.port, "password": e2eTrojanPass, "tls": pin},
		},
		"groups": []any{
			grp("gn_direct", "direct", "ss_n"), grp("gn_anytls", "any_n1", "any_n2"),
			grp("gn_socks", "sk_n1", "sk_n2"), grp("gn_chain", "tj_via", "tj_n2"),
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"domain_suffix": "dir.nref.e2e.test", "outbound": "gn_direct"},
			map[string]any{"domain_suffix": "any.nref.e2e.test", "outbound": "gn_anytls"},
			map[string]any{"domain_suffix": "sk.nref.e2e.test", "outbound": "gn_socks"},
			map[string]any{"domain_suffix": "chain.nref.e2e.test", "outbound": "gn_chain"},
		}},
	})
	echo := w.echoTCP["127.0.0.1"]
	closed := uint16(e2eFreePort(t))
	type nc struct {
		group, suffix, cur, next, what string
		port                           uint16
		switchAfter3                   bool
	}
	cases := []nc{
		{"gn_direct", "dir.nref.e2e.test", "direct", "ss_n", "direct member, destination port closed (local ECONNREFUSED from the destination)", closed, false},
		{"gn_anytls", "any.nref.e2e.test", "any_n1", "any_n2", "AnyTLS server reachable, destination port closed (server refuses the stream)", closed, false},
		{"gn_socks", "sk.nref.e2e.test", "sk_n1", "sk_n2", "SOCKS5 server reachable, destination port closed (SOCKS5 reply)", closed, false},
		{"gn_chain", "chain.nref.e2e.test", "tj_via", "tj_n2", "chain tj_via -> sk_hop: trojan server killed, refusal relayed by the SOCKS5 hop", echo, true},
	}
	for _, g := range cases {
		w.must(g.group+" warm-up", e2eTCP(c.socks, "warm."+g.suffix, echo))
	}
	time.Sleep(2500 * time.Millisecond)
	if n := p.countLines(regexp.MustCompile(`group_switch`)); n != 0 {
		t.Fatalf("switch after warm-up:\n%s", p.text())
	}
	sbTjC.kill()
	time.Sleep(300 * time.Millisecond)
	for _, g := range cases {
		anySwitch := regexp.MustCompile(`kat event=group_switch group=` + g.group + ` `)
		h0 := w.httpCount.Load()
		start := time.Now()
		var results []string
		for k := 1; k <= 2; k++ {
			e := e2eTCP(c.socks, fmt.Sprintf("n%d.%s", k, g.suffix), g.port)
			res := "ok"
			if e != nil {
				res = "FAIL(" + e.Error() + ")"
			}
			results = append(results, res)
			time.Sleep(1500 * time.Millisecond)
			if h := w.httpCount.Load(); h != h0 || p.countLines(anySwitch) != 0 {
				t.Fatalf("%s: failure %d (%s) triggered a re-test/switch (http probes %d->%d):\n%s", g.group, k, res, h0, h, p.text())
			}
			w.logf("NOT_IMMEDIATE %s failure=%d t=+%s result=%s probe_http_requests=%d (unchanged) group_switch=0", g.group, k, time.Since(start).Round(time.Millisecond), res, h0)
		}
		// third failure within 60s: the unchanged rule re-tests
		e := e2eTCP(c.socks, "n3."+g.suffix, g.port)
		res := "ok"
		if e != nil {
			res = "FAIL(" + e.Error() + ")"
		}
		results = append(results, res)
		t3 := time.Now()
		for w.httpCount.Load() == h0 {
			if time.Since(t3) > 5*time.Second {
				t.Fatalf("%s: third failure within 60s did not re-test", g.group)
			}
			time.Sleep(5 * time.Millisecond)
		}
		retest := time.Since(t3)
		sw := regexp.MustCompile(`kat event=group_switch group=` + g.group + ` from=` + g.cur + ` to=` + g.next + `\b`)
		switched := p.waitLines(sw, 1, 3*time.Second)
		if switched != g.switchAfter3 {
			t.Fatalf("%s: switch after the re-test = %v, want %v:\n%s", g.group, switched, g.switchAfter3, p.text())
		}
		time.Sleep(500 * time.Millisecond)
		w.logf("NOTIMM_RESULT group=%s case=%q connections=%v retest_after_failure=3 retest_seen_after=%s probe_http_requests=%d->%d switched_after_retest=%v",
			g.group, g.what, results, retest.Round(time.Millisecond), h0, w.httpCount.Load(), switched)
	}
	w.stopEntry(p)
}
