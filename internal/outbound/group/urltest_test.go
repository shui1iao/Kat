package group

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

const ms_ = time.Millisecond

func TestURLTestFirstUseUsesFirstMemberAndProbes(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 80 * ms_, "c": 150 * ms_})
	p.block = make(chan struct{})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b, c), clk, p, ev)
	g.Start(context.Background())
	if isProbing(g) || g.Current() != "a" {
		t.Fatalf("before use: probing=%v current=%q", isProbing(g), g.Current())
	}
	// first use: first member, probe starts in the background
	if got := dial(t, g, "x.test"); got != "a" {
		t.Fatalf("first dial via %q, want a", got)
	}
	if !isProbing(g) {
		t.Fatal("first use did not start a probe round")
	}
	close(p.block)
	waitRounds(t, g, 1)
	if g.Current() != "b" || dial(t, g, "x.test") != "b" {
		t.Fatalf("after probe current = %q, want lowest-latency b", g.Current())
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != "a>b" {
		t.Fatalf("switch events %v", sw)
	}
	if s := snapMember(g, "c"); !s.ProbeOK || s.ProbeLatency != 150*ms_ {
		t.Fatalf("snapshot c = %+v", s)
	}
}

func TestURLTestTolerance(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 200 * ms_, "b": 250 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, nil) // tolerance default 100ms
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	// b becomes faster, but only by 50ms (< 100ms tolerance): stay on a
	p.set("b", 150*ms_, false)
	clk.Advance(11 * time.Minute)
	dial(t, g, "x.test")
	waitRounds(t, g, 2)
	if g.Current() != "a" {
		t.Fatalf("switched within tolerance: current %q", g.Current())
	}
	// b faster by 110ms (> tolerance): switch
	p.set("b", 90*ms_, false)
	clk.Advance(11 * time.Minute)
	dial(t, g, "x.test")
	waitRounds(t, g, 3)
	if g.Current() != "b" {
		t.Fatalf("not switched beyond tolerance: current %q", g.Current())
	}
}

func TestURLTestToleranceConfigured(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 200 * ms_, "b": 150 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest, Tolerance: outbound.Duration(20 * ms_)}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "b" {
		t.Fatalf("tolerance 20ms, b 50ms faster: current %q", g.Current())
	}
}

func TestURLTestCurrentProbeFailureSwitches(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 180 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	p.set("a", 0, true) // current fails its probe: switch even though b is slower than a was
	clk.Advance(11 * time.Minute)
	dial(t, g, "x.test")
	waitRounds(t, g, 2)
	if g.Current() != "b" {
		t.Fatalf("current failed probe but group stayed on %q", g.Current())
	}
	// all fail: keep the current member
	p.set("b", 0, true)
	clk.Advance(11 * time.Minute)
	dial(t, g, "x.test")
	waitRounds(t, g, 3)
	if g.Current() != "b" {
		t.Fatalf("all failed: current %q, want unchanged b", g.Current())
	}
}

func TestURLTestLazyProbing(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 50 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "https://probe.test/", Interval: outbound.Duration(10 * time.Minute)}},
		members(a, b), clk, p, nil)
	g.Start(context.Background())
	clk.Advance(3 * time.Hour) // never used: never probed
	time.Sleep(20 * ms_)
	if p.count("a")+p.count("b") != 0 || g.roundsRun.Load() != 0 || clk.pending() != 0 {
		t.Fatalf("unused url-test probed: calls a=%d b=%d rounds=%d timers=%d", p.count("a"), p.count("b"), g.roundsRun.Load(), clk.pending())
	}
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	// within the interval: results are reused
	clk.Advance(9 * time.Minute)
	dial(t, g, "x.test")
	if isProbing(g) {
		t.Fatal("re-probed while results still valid")
	}
	// expired but unused: nothing happens
	clk.Advance(2 * time.Hour)
	time.Sleep(20 * ms_)
	if g.roundsRun.Load() != 1 || isProbing(g) {
		t.Fatalf("expired+unused triggered a probe (rounds %d)", g.roundsRun.Load())
	}
	// expired and used: background re-test, the connection is not delayed
	if got := dial(t, g, "x.test"); got != "b" {
		t.Fatalf("dial via %q", got)
	}
	waitRounds(t, g, 2)
	if p.count("a") != 2 || p.count("b") != 2 {
		t.Fatalf("each member must be probed once per round: a=%d b=%d", p.count("a"), p.count("b"))
	}
}

func TestURLTestThreeDialFailuresIn60sRetest(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 100 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	a.setErr(errors.New("refused"))

	// spread over more than 60s: no re-test
	for i := 0; i < 3; i++ {
		if got := dial(t, g, "x.test"); got != "b" { // retried on b
			t.Fatalf("dial %d via %q", i, got)
		}
		clk.Advance(31 * time.Second)
	}
	time.Sleep(20 * ms_)
	if g.roundsRun.Load() != 1 || isProbing(g) {
		t.Fatalf("3 failures over 62s triggered a re-test")
	}
	if s := snapMember(g, "a"); s.Failures != 1 {
		t.Fatalf("failures in window = %d, want 1", s.Failures)
	}
	// two more within 60s (3 in window): immediate re-test
	dial(t, g, "x.test")
	clk.Advance(5 * time.Second)
	p.set("a", 0, true)
	dial(t, g, "x.test")
	waitRounds(t, g, 2)
	if g.Current() != "b" {
		t.Fatalf("after re-test current %q, want b", g.Current())
	}
}
