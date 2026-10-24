package kernel

// Real-process end-to-end tests: an automatic group whose first member has
// wrong credentials (SS2022 key / Trojan password) must stop sending new
// connections to it. Same gating and fixtures as routing_e2e_test.go
// (both KAT_E2E_KAT and KAT_INTEROP_SINGBOX must be set; otherwise the
// tests are skipped).
//
// SS and Trojan send their request header with the first client write, so a
// wrong credential cannot be seen while dialing: the member's dial succeeds,
// the server drops the connection after the first write, and the group does
// not replay client data. The first connection through such a member is
// therefore allowed to fail; what is checked is that the group degrades it
// and that later connections reach the correct member.
//
// Phase A ("wrong from the start"): members [bad, good] where bad has a wrong
// credential from the beginning; the first probe round (lazy on first use for
// url-test/fallback, at start-up for smart) sees the bad member fail.
//
// Phase B ("credential rotated after a successful probe"): members [rot, good]
// with a correct credential for rot; after the first probe round has marked
// rot healthy, rot's server is restarted with a different key/password. The
// probe interval is 10m, so only real connection failures (written, then zero
// bytes back) can trigger the degradation.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var e2eWrongKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 16))

const e2eWrongTrojanPass = "e2e-trojan-wrong-pass"

func TestE2ECredentialFallback(t *testing.T) { e2eCredential(t, "fallback") }
func TestE2ECredentialURLTest(t *testing.T)  { e2eCredential(t, "url-test") }
func TestE2ECredentialSmart(t *testing.T)    { e2eCredential(t, "smart") }

type credCase struct {
	group, suffix, proto string
	bad, good            *e2eFwd
	goodProc             *e2eProc
	rotProc              *e2eProc // phase B only
}

func e2eCredential(t *testing.T, kind string) {
	w := e2eSetup(t)
	sbss, sbtr := w.sbSS("sb-ss", 0), w.sbTrojan("sb-trojan")
	sbssRot, sbtrRot := w.sbSS("sb-ss-rot", 0), w.sbTrojan("sb-trojan-rot")
	// One counting forwarder per member, so every connection attempt is
	// attributed to exactly one member. Phase B good members are 150ms slower
	// so that every group type starts on the rot member.
	fSSBad, fSSGood := w.forwarder("ss_bad", sbss.port, 0), w.forwarder("ss_good", sbss.port, 0)
	fTrBad, fTrGood := w.forwarder("tj_bad", sbtr.port, 0), w.forwarder("tj_good", sbtr.port, 0)
	fSSRot, fSSGood2 := w.forwarder("ss_rot", sbssRot.port, 0), w.forwarder("ss_good2", sbss.port, 150*time.Millisecond)
	fTrRot, fTrGood2 := w.forwarder("tj_rot", sbtrRot.port, 0), w.forwarder("tj_good2", sbtr.port, 150*time.Millisecond)
	all := []*e2eFwd{fSSBad, fSSGood, fTrBad, fTrGood, fSSRot, fSSGood2, fTrRot, fTrGood2}

	pin := map[string]any{"pin_sha256": w.pin}
	ss := func(name string, f *e2eFwd, key string) map[string]any {
		return map[string]any{"name": name, "type": "shadowsocks", "server": "127.0.0.1", "port": f.port, "method": e2eMethod, "key": key}
	}
	tj := func(name string, f *e2eFwd, pass string) map[string]any {
		return map[string]any{"name": name, "type": "trojan", "server": "127.0.0.1", "port": f.port, "password": pass, "tls": pin}
	}
	probe := map[string]any{"url": "http://127.0.0.1:" + strconv.Itoa(w.httpPort) + "/", "interval": "10m", "timeout": "2s"}
	grp := func(name string, members ...any) map[string]any {
		return map[string]any{"name": name, "type": kind, "members": members, "probe": probe}
	}
	p, c := w.entry(map[string]any{
		"dns": map[string]any{"server": w.dnsServer()},
		"outbounds": []any{
			ss("ss_bad", fSSBad, e2eWrongKey), ss("ss_good", fSSGood, e2eSBKey),
			tj("tj_bad", fTrBad, e2eWrongTrojanPass), tj("tj_good", fTrGood, e2eTrojanPass),
			ss("ss_rot", fSSRot, e2eSBKey), ss("ss_good2", fSSGood2, e2eSBKey),
			tj("tj_rot", fTrRot, e2eTrojanPass), tj("tj_good2", fTrGood2, e2eTrojanPass),
		},
		"groups": []any{
			grp("gssA", "ss_bad", "ss_good"), grp("gtjA", "tj_bad", "tj_good"),
			grp("gssB", "ss_rot", "ss_good2"), grp("gtjB", "tj_rot", "tj_good2"),
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"domain_suffix": "ssa.e2e.test", "outbound": "gssA"},
			map[string]any{"domain_suffix": "tja.e2e.test", "outbound": "gtjA"},
			map[string]any{"domain_suffix": "ssb.e2e.test", "outbound": "gssB"},
			map[string]any{"domain_suffix": "tjb.e2e.test", "outbound": "gtjB"},
		}},
	})
	entryStart := time.Now()
	e1 := w.echoTCP["127.0.0.1"]

	// ---- phase A: wrong credential from the start ----
	for _, cc := range []credCase{
		{group: "gssA", suffix: "ssa.e2e.test", proto: "ss2022", bad: fSSBad, good: fSSGood, goodProc: sbss},
		{group: "gtjA", suffix: "tja.e2e.test", proto: "trojan", bad: fTrBad, good: fTrGood, goodProc: sbtr},
	} {
		w.logf("phase A %s group=%s: first connection %s after entry start", kind, cc.group, time.Since(entryStart).Round(time.Millisecond))
		w.credRun(p, c, kind, "A(wrong-from-start)", cc, e1, all)
	}

	// ---- phase B: credential rotated on the server after a good probe ----
	cases := []credCase{
		{group: "gssB", suffix: "ssb.e2e.test", proto: "ss2022", bad: fSSRot, good: fSSGood2, goodProc: sbss, rotProc: sbssRot},
		{group: "gtjB", suffix: "tjb.e2e.test", proto: "trojan", bad: fTrRot, good: fTrGood2, goodProc: sbtr, rotProc: sbtrRot},
	}
	for _, cc := range cases {
		// Warm-up: first use starts the lazy probe round (url-test/fallback);
		// the connection itself must go through the (still correct) rot member.
		w.credWarm(c, "warm", cc, e1)
	}
	// Let every probe round finish (loopback probes take milliseconds; timeout 2s).
	time.Sleep(2500 * time.Millisecond)
	if strings.Contains(p.text(), "group=gssB") || strings.Contains(p.text(), "group=gtjB") {
		t.Fatalf("phase B group switched before rotation:\n%s", p.text())
	}
	// Second warm-up after the probe round: still on rot (probe said healthy).
	for _, cc := range cases {
		w.credWarm(c, "warm2", cc, e1)
	}
	// Rotate: restart both rot servers with a different key / password.
	w.rotate(sbssRot, func(in map[string]any) { in["password"] = e2eWrongKey })
	w.rotate(sbtrRot, func(in map[string]any) {
		in["users"] = []any{map[string]any{"name": "u", "password": e2eWrongTrojanPass}}
	})
	for _, cc := range cases {
		w.credRun(p, c, kind, "B(rotated-after-probe)", cc, e1, all)
	}
	w.stopEntry(p)
}

// credWarm makes one connection that must be served by the rot member's
// server (sing-box connection log lines; forwarder counters would also count
// the probe round started by the first use).
func (w *e2eWorld) credWarm(c *e2eClients, label string, cc credCase, echo uint16) {
	w.t.Helper()
	re := sbConn(echo)
	nr, ng := cc.rotProc.countLines(re), cc.goodProc.countLines(re)
	w.must(fmt.Sprintf("phase B %s %s connection", cc.group, label), e2eTCP(c.socks, label+"."+cc.suffix, echo))
	if !cc.rotProc.waitLines(re, nr+1, 3*time.Second) || cc.goodProc.countLines(re) != ng {
		w.t.Fatalf("phase B %s %s: not served by %s (rot lines %d->%d, good lines %d->%d)", cc.group, label, cc.rotProc.name,
			nr, cc.rotProc.countLines(re), ng, cc.goodProc.countLines(re))
	}
	w.logf("EVIDENCE phase B %s %s: served by %s (lines %d->%d), %s unchanged (%d)", cc.group, label, cc.rotProc.name, nr, cc.rotProc.countLines(re), cc.goodProc.name, ng)
}

// rotate rewrites a sing-box server's inbound and restarts it on the same port.
func (w *e2eWorld) rotate(sp *e2eProc, mut func(in map[string]any)) {
	b, e := os.ReadFile(sp.cfgPath)
	if e != nil {
		w.t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(b, &cfg); e != nil {
		w.t.Fatal(e)
	}
	mut(cfg["inbounds"].([]any)[0].(map[string]any))
	if b, e = json.MarshalIndent(cfg, "", "  "); e != nil {
		w.t.Fatal(e)
	}
	if e = os.WriteFile(sp.cfgPath, b, 0600); e != nil {
		w.t.Fatal(e)
	}
	sp.kill()
	sp.start()
	w.logf("rotated credential of %s (restarted on port %d)", sp.name, sp.port)
}

// credRun makes paced client connections through cc.group until one succeeds
// (at most 12), then three more that must all succeed via the good member
// with zero attempts on the bad member. It records the outcome sequence,
// recovery count/time and the switch event.
func (w *e2eWorld) credRun(p *e2eProc, c *e2eClients, kind, phase string, cc credCase, echo uint16, all []*e2eFwd) {
	t := w.t
	t.Helper()
	sbRE := sbConn(echo)
	start := time.Now()
	var seq []string
	failed, firstOK := 0, -1
	firstResult := ""
	for i := 1; i <= 12; i++ {
		s := snapshot(all...)
		goodLines := cc.goodProc.countLines(sbRE)
		t0 := time.Now()
		e := e2eTCP(c.socks, fmt.Sprintf("c%d.%s", i, cc.suffix), echo)
		d := delta(s, cc.bad, cc.good)
		res := "ok"
		if e != nil {
			res = "FAIL(" + e.Error() + ")"
			failed++
		}
		if i == 1 {
			firstResult = res
		}
		w.logf("CONN %s phase=%s group=%s #%d t=+%s took=%s result=%s fwd_tcp_incl_probes %s=%d %s=%d good_server_lines %d->%d",
			kind, phase, cc.group, i, time.Since(start).Round(time.Millisecond), time.Since(t0).Round(time.Millisecond), res,
			cc.bad.name, d[cc.bad.name][0], cc.good.name, d[cc.good.name][0], goodLines, cc.goodProc.countLines(sbRE))
		seq = append(seq, map[bool]string{true: "ok", false: "fail"}[e == nil])
		if e == nil {
			firstOK = i
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if firstOK < 0 {
		t.Fatalf("%s %s: no connection succeeded after 12 attempts:\n%s", phase, cc.group, p.text())
	}
	recovery := time.Since(start)
	sw := regexp.MustCompile(`kat event=group_switch group=` + cc.group + ` from=` + cc.bad.name + ` to=` + cc.good.name)
	if !p.waitLines(sw, 1, 5*time.Second) {
		t.Fatalf("%s %s: no group_switch to the good member:\n%s", phase, cc.group, p.text())
	}
	// After recovery: new connections go to the good member only.
	s := snapshot(all...)
	goodLines := cc.goodProc.countLines(sbRE)
	for i := 1; i <= 3; i++ {
		w.must(fmt.Sprintf("%s %s %s connection after recovery %d", kind, phase, cc.group, i), e2eTCP(c.socks, fmt.Sprintf("after%d.%s", i, cc.suffix), echo))
	}
	if !cc.goodProc.waitLines(sbRE, goodLines+3, 3*time.Second) {
		t.Fatalf("%s %s: post-recovery connections not seen by the good server", phase, cc.group)
	}
	w.expect(fmt.Sprintf("%s %s %s post-recovery: 3 connections, all on %s, none on %s", kind, phase, cc.group, cc.good.name, cc.bad.name),
		delta(s, cc.bad, cc.good), map[string][2]int64{cc.bad.name: {0, 0}, cc.good.name: {3, 0}})
	w.logf("CRED_RESULT kind=%s phase=%s proto=%s group=%s first_connection=%s failed_before_recovery=%d recovered_at_connection=%d recovery_time=%s sequence=%s switch_event=%q good_server_lines=%d->%d probe_http_requests_total=%d",
		kind, phase, cc.proto, cc.group, firstResult, failed, firstOK, recovery.Round(time.Millisecond), strings.Join(seq, ","),
		sw.String(), goodLines, cc.goodProc.countLines(sbRE), w.httpCount.Load())
}
