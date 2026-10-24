package group

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFallbackOrderPreference(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 400 * ms_, "b": 20 * ms_, "c": 10 * ms_})
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b, c), clk, p, nil)
	g.Start(context.Background())
	if dial(t, g, "x.test") != "a" { // first use before results: first member
		t.Fatal("first use not on a")
	}
	waitRounds(t, g, 1)
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("fallback must follow order, not latency: current %q", g.Current())
	}
}

func TestFallbackFirstFailsUsesSecond(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 10 * ms_, "b": 20 * ms_, "c": 30 * ms_})
	p.fail["a"] = true
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b, c), clk, p, ev)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "b" || dial(t, g, "x.test") != "b" {
		t.Fatalf("a failed its probe: current %q, want b", g.Current())
	}
	// real dial failures on b (probe still fine): after 2 in a row, c takes over
	b.setErr(errors.New("refused"))
	if got := dial(t, g, "x.test"); got != "c" { // retried on c; one failure keeps b
		t.Fatalf("retry via %q", got)
	}
	if g.Current() != "b" {
		t.Fatalf("one failure switched to %q", g.Current())
	}
	dial(t, g, "x.test")
	if g.Current() != "c" {
		t.Fatalf("two consecutive real failures: current %q, want c", g.Current())
	}
	if sw := switches(ev); len(sw) != 2 || sw[0] != "a>b" || sw[1] != "b>c" {
		t.Fatalf("switches %v", sw)
	}
}

func TestFallbackSwitchesBackWhenFirstRecovers(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 10 * ms_, "b": 20 * ms_})
	p.fail["a"] = true
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b), clk, p, ev)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "b" {
		t.Fatalf("current %q", g.Current())
	}
	p.set("a", 10*ms_, false) // a recovers; next (lazy) round notices
	clk.Advance(11 * time.Minute)
	if got := dial(t, g, "x.test"); got != "b" { // round runs in background
		t.Fatalf("dial via %q", got)
	}
	waitRounds(t, g, 2)
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("did not switch back to a: %q", g.Current())
	}
	if sw := switches(ev); len(sw) != 2 || sw[1] != "b>a" {
		t.Fatalf("switches %v", sw)
	}

	// recovery after real failures: a probe success brings the member back
	a.setErr(errors.New("refused"))
	dial(t, g, "x.test")
	dial(t, g, "x.test")
	if g.Current() != "b" {
		t.Fatalf("a failed twice: current %q", g.Current())
	}
	a.setErr(nil)
	clk.Advance(11 * time.Minute)
	dial(t, g, "x.test")
	waitRounds(t, g, 3)
	if g.Current() != "a" {
		t.Fatalf("a probe-recovered but current %q", g.Current())
	}
}

func TestFallbackAllDownUsesFirst(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{})
	p.fail["a"], p.fail["b"] = true, true
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("all down: current %q, want first member a", g.Current())
	}
}
