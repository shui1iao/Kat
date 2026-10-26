package group

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func testLB(t *testing.T, strategy string, clk *fakeClock, names ...string) *autoGroup {
	t.Helper()
	ms := make([]outbound.Outbound, len(names))
	for i, n := range names {
		ms[i] = newFake(n)
	}
	gr, e := newGroup(Options{Name: "lb", Type: TypeLoadBalance, Members: names, Strategy: strategy, Probe: &ProbeOptions{URL: "http://127.0.0.1:9"}}, ms, nil, hooks{clk: clk})
	if e != nil {
		t.Fatal(e)
	}
	g := gr.(*autoGroup)
	t.Cleanup(func() { g.Close() })
	return g
}
func TestLoadBalanceDistributionAndRemoval(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.1")
	clk := newFakeClock()
	g := testLB(t, StrategyRoundRobin, clk, "a", "b", "c")
	counts := map[int]int{}
	for i := 0; i < 300; i++ {
		counts[g.lbPick(src, "example.com", false, nil)[0]]++
	}
	if counts[0] != 100 || counts[1] != 100 || counts[2] != 100 {
		t.Fatal(counts)
	}
	t.Logf("RR 300 connections: %v", counts)
	h := testLB(t, StrategyConsistentHashing, clk, "a", "b", "c")
	after := testLB(t, StrategyConsistentHashing, clk, "a", "c")
	count := map[string]int{}
	moved := 0
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("site-%d.example", i)
		a := h.cfg.members[h.lbPick(src, key, false, nil)[0]]
		if b := h.cfg.members[h.lbPick(src, key, false, nil)[0]]; a != b {
			t.Fatal("unstable")
		}
		b := after.cfg.members[after.lbPick(src, key, false, nil)[0]]
		count[a]++
		if a != b {
			moved++
			if a != "b" {
				t.Fatalf("unrelated key moved: %s -> %s", a, b)
			}
		}
	}
	if moved != count["b"] || moved < 2500 || moved > 4200 {
		t.Fatal(moved, count)
	}
	t.Logf("HRW 10000 keys distribution=%v removed=b moved=%d unrelated=0", count, moved)
	for a, b := range map[string]string{"a.b.example.co.uk": "example.co.uk", "EXAMPLE.COM.": "example.com", "127.0.0.1": "127.0.0.1", "::1": "::1", "localhost": "localhost"} {
		if DestinationKey(a) != b {
			t.Fatal(a, DestinationKey(a), b)
		}
	}
}
func TestLoadBalanceStickyTTLSourceHealth(t *testing.T) {
	clk := newFakeClock()
	g := testLB(t, StrategyStickySessions, clk, "a", "b", "c")
	src := netip.MustParseAddr("192.0.2.1")
	key := "example.com"
	a := g.lbPick(src, key, false, nil)[0]
	start := clk.Now()
	skey := src.String() + "|" + key
	for i := 0; i < 10; i++ {
		if g.lbPick(src, key, false, nil)[0] != a {
			t.Fatal("not sticky")
		}
	}
	clk.Advance(9 * time.Minute)
	g.lbPick(src, key, false, nil)
	if !g.lb.sticky[skey].expires.Equal(start.Add(10 * time.Minute)) {
		t.Fatal("TTL renewed")
	}
	other := netip.MustParseAddr("192.0.2.2")
	g.lbPick(other, key, false, nil)
	if len(g.lb.sticky) != 2 {
		t.Fatal("source not included")
	}
	clk.Advance(time.Minute)
	g.lbPick(src, key, false, nil)
	if !g.lb.sticky[skey].expires.Equal(clk.Now().Add(10 * time.Minute)) {
		t.Fatal("not expired")
	}
	a = g.lbPick(src, key, false, nil)[0]
	g.st[a].probed = true
	g.st[a].probeOK = false
	if b := g.lbPick(src, key, false, nil)[0]; b == a {
		t.Fatal("failed probe not skipped")
	}
	g.realSuccess(a, key, 0, false)
	if !g.lbUpLocked(a) {
		t.Fatal("successful connection did not restore health")
	}
	for i := 0; i < g.cfg.maxFailed; i++ {
		g.realFailure(a, key, false)
	}
	if g.lbUpLocked(a) {
		t.Fatal("real failures not skipped")
	}
	if b := g.lbPick(src, key, false, nil)[0]; b == a {
		t.Fatal("sticky member still down")
	}
	g.realSuccess(a, key, 0, false)
	if !g.lbUpLocked(a) {
		t.Fatal("not restored")
	}
	t.Log("sticky source isolation, fixed 10m TTL, failed-probe skip, max-failure skip, traffic recovery passed")
}
func TestLoadBalanceUDPDispatch(t *testing.T) {
	g := testLB(t, StrategyRoundRobin, newFakeClock(), "a", "b", "c")
	ctx, cancel := context.WithCancel(outbound.WithSource(context.Background(), netip.MustParseAddr("192.0.2.1")))
	pc, e := g.ListenPacket(ctx)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	defer pc.Close()
	p := pc.(*lbPacket)
	for i, h := range []string{"one.com", "two.net", "three.org"} {
		dst := outbound.Addr{Host: h, Port: 53}
		if _, e := p.WriteTo([]byte("query"), dst); e != nil {
			t.Fatal(e)
		}
		if p.MemberFor(dst) != g.cfg.members[i] {
			t.Fatal("RR UDP member", p.MemberFor(dst))
		}
		f := g.members[i].(*fakeOut)
		f.lastPC.in <- []byte(h)
		p.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, _, e := p.ReadFrom(buf)
		if e != nil || string(buf[:n]) != h || p.ReadMember() != g.cfg.members[i] {
			t.Fatal("reply", n, e, p.ReadMember())
		}
		if p.MemberFor(outbound.Addr{Host: h, Port: 123}) != g.cfg.members[i] {
			t.Fatal("port affects key")
		}
	}
	if len(p.subs) != 3 || len(p.route) != 3 {
		t.Fatal("wrong UDP fanout")
	}
	t.Log("UDP 3 target keys -> a,b,c; replies identify member; canceled setup context does not kill delayed sessions")
}
func TestGroupNewParameterValidation(t *testing.T) {
	base := Options{Name: "g", Type: TypeLoadBalance, Members: []string{"a"}, Probe: &ProbeOptions{URL: "http://127.0.0.1:9"}}
	for _, f := range []func(*Options){func(o *Options) { o.Strategy = "bad" }, func(o *Options) { o.MaxFailedTimes = -1 }, func(o *Options) { o.StickyTTL = 1 }, func(o *Options) { o.Filter = "(?=x)" }, func(o *Options) { o.Tolerance = 1 }, func(o *Options) { o.Probe = &ProbeOptions{URL: "http://127.0.0.1:9", ExpectedStatus: "600"} }} {
		o := base
		f(&o)
		if Validate(o) == nil {
			t.Fatalf("accepted %#v", o)
		}
	}
	for _, s := range []string{"204", "200/204", "200-299/302", "*"} {
		f, e := parseExpectedStatus(s)
		if e != nil || !f(204) || s != "*" && f(500) {
			t.Fatal(s, e)
		}
	}
	keep, e := MemberFilter(Options{Filter: "香港`日本", ExcludeFilter: "过期", ExcludeType: "ss"})
	if e != nil || !keep("香港 1", "trojan") || keep("香港过期", "trojan") || keep("日本", "shadowsocks") || keep("美国", "anytls") {
		t.Fatal("filter", e)
	}
}
func TestProbeExpectedStatusActualHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	for _, c := range []struct {
		status string
		ok     bool
	}{{"", true}, {"204", false}, {"200-499", true}, {"*", true}} {
		cfg, e := normalize(Options{Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{URL: srv.URL, ExpectedStatus: c.status}})
		if e != nil {
			t.Fatal(e)
		}
		p := httpProber{url: cfg.url, target: cfg.target, clk: realClock{}, expected: cfg.expected}
		_, e = p.probe(context.Background(), &loopOut{name: "a"})
		if (e == nil) != c.ok {
			t.Fatal(c, e)
		}
	}
}
func TestLazyFalseAndMaxFailed(t *testing.T) {
	for _, lazy := range []bool{true, false} {
		clk := newFakeClock()
		f := newFake("a")
		g0, e := newGroup(Options{Name: "g", Type: TypeLoadBalance, Members: []string{"a"}, Lazy: &lazy, MaxFailedTimes: 2, Probe: &ProbeOptions{URL: "http://127.0.0.1:9", Interval: outbound.Duration(time.Second)}}, []outbound.Outbound{f}, nil, hooks{clk: clk, probe: func(context.Context, outbound.Outbound) (time.Duration, error) { return time.Millisecond, nil }})
		if e != nil {
			t.Fatal(e)
		}
		g := g0.(*autoGroup)
		g.Start(context.Background())
		if lazy {
			if g.roundsRun.Load() != 0 {
				t.Fatal("lazy start probed")
			}
			g.lbPick(netip.Addr{}, "x", false, nil)
		}
		waitRound(t, g, 1)
		if !lazy {
			clk.Advance(time.Second)
			waitRound(t, g, 2)
		}
		g.realFailure(0, "x", false)
		g.realFailure(0, "x", false)
		waitRound(t, g, g.roundsRun.Load())
		g.Close()
	}
	// Exact threshold without an asynchronous successful probe racing the assertion.
	g := testLB(t, StrategyRoundRobin, newFakeClock(), "a", "b")
	g.cfg.maxFailed = 2
	g.realFailure(0, "x", false)
	if !g.lbUpLocked(0) {
		t.Fatal("failed before threshold")
	}
	g.realFailure(0, "x", false)
	if g.lbUpLocked(0) {
		t.Fatal("not failed at threshold")
	}
	for i := range g.st {
		g.st[i].probed = true
		g.st[i].probeOK = false
	}
	if len(g.lbPick(netip.Addr{}, "x", false, nil)) != 2 {
		t.Fatal("all-down fallback")
	}
}
func waitRound(t *testing.T, g *autoGroup, n int64) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for g.roundsRun.Load() < n && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if g.roundsRun.Load() < n {
		t.Fatal("probe round timeout", n)
	}
}

func TestGroupNewParameterThresholdMappings(t *testing.T) {
	for _, typ := range []string{TypeFallback, TypeURLTest} {
		p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond, "b": time.Millisecond})
		g := newAuto(t, Options{Type: typ, MaxFailedTimes: 4}, members(newFake("a"), newFake("b")), newFakeClock(), p, nil)
		g.Start(context.Background())
		for i := 0; i < 3; i++ {
			g.realFailure(0, "x", false)
		}
		if typ == TypeFallback && g.Current() != "a" {
			t.Fatal("fallback switched before configured threshold")
		}
		if typ == TypeURLTest && isProbing(g) {
			t.Fatal("url-test probed before threshold")
		}
		g.realFailure(0, "x", false)
		if typ == TypeFallback && g.Current() != "b" {
			t.Fatal("fallback did not switch at configured threshold")
		}
		if typ == TypeURLTest {
			waitRounds(t, g, 1)
		}
		t.Logf("%s max_failed_times=4: no action after 3 failures, action at 4", typ)
	}
}
