package group

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// long interval: no periodic rounds unless a test advances that far
var smartLong = &ProbeOptions{URL: "http://probe.test/", Interval: outbound.Duration(10 * time.Hour)}

func setEWMA(g *autoGroup, name string, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, n := range g.cfg.members {
		if n == name {
			g.st[i].ewma, g.st[i].hasEWMA = d, true
		}
	}
}

func near(a, b time.Duration) bool { return math.Abs(float64(a-b)) <= float64(time.Microsecond) }

func TestSmartColdStartOrder(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 100 * ms_, "c": 200 * ms_})
	p.block = make(chan struct{})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b, c), clk, p, ev)
	g.Start(context.Background())
	if !isProbing(g) {
		t.Fatal("smart did not probe immediately on Start")
	}
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("cold start current %q, want first member", g.Current())
	}
	close(p.block)
	waitRounds(t, g, 1)
	if g.Current() != "b" {
		t.Fatalf("after first round current %q, want best b (no hysteresis at cold start)", g.Current())
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != "a>b" {
		t.Fatalf("switches %v", sw)
	}

	// before any data, the retry order is the configuration order too
	clk2 := newFakeClock()
	a2, b2, c2 := newFake("a"), newFake("b"), newFake("c")
	p2 := newFakeProbe(map[string]time.Duration{})
	p2.block = make(chan struct{})
	defer close(p2.block)
	g2 := newAuto(t, Options{Type: TypeSmart, Priority: map[string]float64{}}, members(c2, a2, b2), clk2, p2, nil)
	g2.Start(context.Background())
	c2.setErr(errors.New("down"))
	if got := dial(t, g2, "y.test"); got != "a" {
		t.Fatalf("cold retry via %q, want a (second in configuration order)", got)
	}
}

func TestSmartEWMASmoothsOutlier(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 400 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	p.set("a", 1000*ms_, false) // one anomalous sample
	probeNow(t, g)
	if l := snapMember(g, "a").Latency; !near(l, 370*ms_) {
		t.Fatalf("EWMA after outlier = %v, want 370ms (0.3*1000+0.7*100)", l)
	}
	if g.Current() != "a" {
		t.Fatalf("single outlier moved the group to %q", g.Current())
	}
	p.set("a", 100*ms_, false)
	probeNow(t, g)
	if l := snapMember(g, "a").Latency; !near(l, 289*ms_) {
		t.Fatalf("EWMA = %v, want 289ms", l)
	}
}

func TestSmartPenaltyAccumulatesAndDecays(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 100 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	p.set("a", 0, true)
	for _, want := range []time.Duration{300 * ms_, 900 * ms_, 2100 * ms_} {
		probeNow(t, g)
		if s := snapMember(g, "a"); s.Penalty != want {
			t.Fatalf("penalty = %v, want %v (failures %d)", s.Penalty, want, s.Failures)
		}
	}
	if s := snapMember(g, "a"); s.Failures != 3 || s.Score != 2200*ms_ {
		t.Fatalf("snapshot %+v, want 3 failures, score 100+2100", s)
	}
	clk.Advance(5 * time.Minute) // one half-life
	if s := snapMember(g, "a"); s.Penalty != 1050*ms_ {
		t.Fatalf("after 5m penalty = %v, want 1050ms", s.Penalty)
	}
	clk.Advance(5 * time.Minute)
	if s := snapMember(g, "a"); s.Penalty != 525*ms_ {
		t.Fatalf("after 10m penalty = %v, want 525ms", s.Penalty)
	}
	// success resets the consecutive count (not the decaying penalty) ...
	p.set("a", 100*ms_, false)
	probeNow(t, g)
	if s := snapMember(g, "a"); s.Failures != 0 || s.Penalty != 525*ms_ {
		t.Fatalf("after success %+v", s)
	}
	// ... so the next failure adds 300ms again
	p.set("a", 0, true)
	probeNow(t, g)
	if s := snapMember(g, "a"); s.Penalty != 825*ms_ {
		t.Fatalf("penalty after reset = %v, want 825ms", s.Penalty)
	}
	// cap 10s
	for i := 0; i < 10; i++ {
		probeNow(t, g)
	}
	if s := snapMember(g, "a"); s.Penalty != 10*time.Second {
		t.Fatalf("penalty cap = %v, want 10s", s.Penalty)
	}
}

func TestSmartPriorityChangesChoice(t *testing.T) {
	for _, tc := range []struct {
		prio map[string]float64
		want string
	}{
		{nil, "a"},
		{map[string]float64{"b": 0.5}, "b"},  // 120*0.5 = 60 < 100
		{map[string]float64{"a": 2}, "b"},    // 200 > 120
		{map[string]float64{"b": 1.5}, "a"},  // 180 > 100
		{map[string]float64{"a": 0.01}, "a"}, // tiny factor keeps a
	} {
		clk := newFakeClock()
		a, b := newFake("a"), newFake("b")
		p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 120 * ms_})
		g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong, Priority: tc.prio}, members(a, b), clk, p, nil)
		g.Start(context.Background())
		waitRounds(t, g, 1)
		if g.Current() != tc.want || dial(t, g, "x.test") != tc.want {
			t.Fatalf("priority %v: current %q, want %q", tc.prio, g.Current(), tc.want)
		}
	}
}

func TestSmartHysteresis(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 200 * ms_, "b": 300 * ms_})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, ev)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	clk.Advance(61 * time.Second) // dwell satisfied from here on
	setEWMA(g, "b", 175*ms_)      // 12.5% and 25ms better: no
	if dial(t, g, "x.test") != "a" {
		t.Fatal("switched for 25ms/12.5%")
	}
	setEWMA(g, "b", 165*ms_) // 35ms but only 17.5% better: no
	if dial(t, g, "x.test") != "a" {
		t.Fatal("switched for <20%")
	}
	setEWMA(g, "b", 160*ms_) // 40ms and 20%: yes
	if dial(t, g, "x.test") != "b" || g.Current() != "b" {
		t.Fatal("did not switch at 20%/40ms after 60s")
	}
	// 30ms floor on small scores: a is 25% better but only 25ms
	setEWMA(g, "b", 100*ms_)
	setEWMA(g, "a", 75*ms_)
	clk.Advance(2 * time.Minute)
	if dial(t, g, "x.test") != "b" {
		t.Fatal("switched for 25ms")
	}
	// dwell: much better candidate, but b became current less than 60s ago
	clk2 := newFakeClock()
	g2 := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(newFake("a"), newFake("b")), clk2, p, nil)
	g2.Start(context.Background())
	waitRounds(t, g2, 1) // a current at t0
	setEWMA(g2, "b", 50*ms_)
	clk2.Advance(59 * time.Second)
	if dial(t, g2, "x.test") != "a" {
		t.Fatal("switched before 60s dwell")
	}
	clk2.Advance(time.Second)
	if dial(t, g2, "x.test") != "b" {
		t.Fatal("did not switch after 60s dwell")
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != "a>b" {
		t.Fatalf("switches %v", sw)
	}
}

func TestSmartCurrentFailureSwitchesImmediately(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 1000 * ms_})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, ev)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	a.setErr(errors.New("refused"))
	// no dwell, and a (100+300) would still score better than b (1000)
	if got := dial(t, g, "x.test"); got != "b" {
		t.Fatalf("retry via %q", got)
	}
	if g.Current() != "b" {
		t.Fatalf("current %q after current failed", g.Current())
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != "a>b" {
		t.Fatalf("switches %v", sw)
	}
}

func TestSmartSiteMemory(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 100 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	// x.test fails on a: data written, connection closed with zero bytes back
	c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 443})
	if err != nil || ownerOf(c) != "a" {
		t.Fatalf("dial: %v %s", err, ownerOf(c))
	}
	peer := <-a.peers
	go func() { buf := make([]byte, 64); peer.Read(buf); peer.Close() }()
	c.Write([]byte("hello"))
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("expected EOF")
	}
	c.Close()
	if g.Current() != "b" {
		t.Fatalf("current %q after failure", g.Current())
	}
	// a recovers globally 20 minutes later (probe success, penalty decayed to 18.75ms)
	clk.Advance(20 * time.Minute)
	probeNow(t, g)
	if g.Current() != "a" {
		t.Fatalf("a recovered but current %q (snapshot %+v)", g.Current(), g.Snapshot())
	}
	if got := dial(t, g, "y.test"); got != "a" {
		t.Fatalf("other site via %q, want a", got)
	}
	if got := dial(t, g, "x.test"); got != "b" {
		t.Fatalf("x.test via %q, want b (a failed for this site)", got)
	}
	if got := dial(t, g, "1.2.3.4"); got != "a" {
		t.Fatalf("IP site via %q", got)
	}
	// the site memory expires after one hour
	clk.Advance(41 * time.Minute)
	if got := dial(t, g, "x.test"); got != "a" {
		t.Fatalf("x.test after 1h via %q, want a", got)
	}
}

func TestSmartSiteStickiness(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 140 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	// z.test recently succeeded on b: b is preferred there while not >50% slower than the best
	g.mu.Lock()
	g.sites.record("z.test", 1, true, clk.Now())
	g.mu.Unlock()
	if got := dial(t, g, "z.test"); got != "b" {
		t.Fatalf("z.test via %q, want sticky b", got)
	}
	if got := dial(t, g, "w.test"); got != "a" {
		t.Fatalf("w.test via %q, want a", got)
	}
	setEWMA(g, "b", 151*ms_)
	if got := dial(t, g, "z.test"); got != "a" {
		t.Fatalf("b >50%% slower but z.test still via %q", got)
	}
}

func TestSiteCacheBoundedLRU(t *testing.T) {
	c := newSiteCache(smartSiteCap)
	now := time.Now()
	for i := 0; i < smartSiteCap+100; i++ {
		c.record(fmt.Sprintf("s%d.test", i), 0, true, now)
	}
	if c.len() != smartSiteCap {
		t.Fatalf("len = %d, want %d", c.len(), smartSiteCap)
	}
	if c.get("s0.test", now) != nil || c.get(fmt.Sprintf("s%d.test", smartSiteCap+99), now) == nil {
		t.Fatal("LRU eviction order wrong")
	}
	if c.get(fmt.Sprintf("s%d.test", smartSiteCap+99), now.Add(time.Hour)) != nil {
		t.Fatal("entry not expired after 1h")
	}
}

// smartPair builds a started smart group whose current member is a.
func smartPair(t *testing.T) (*autoGroup, *fakeClock, *fakeOut, *fakeOut) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	return g, clk, a, b
}

func dialPeer(t *testing.T, g *autoGroup, f *fakeOut) (net.Conn, net.Conn) {
	t.Helper()
	c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "t.test", Port: 443})
	if err != nil || ownerOf(c) != f.name {
		t.Fatalf("dial: %v via %s", err, ownerOf(c))
	}
	return c, <-f.peers
}

func TestSmartObservesRealConnections(t *testing.T) {
	t.Run("first-response time feeds EWMA", func(t *testing.T) {
		g, clk, a, _ := smartPair(t)
		c, peer := dialPeer(t, g, a)
		defer c.Close()
		got, reply := make(chan struct{}), make(chan struct{})
		go func() { buf := make([]byte, 3); io.ReadFull(peer, buf); close(got); <-reply; peer.Write([]byte("x")) }()
		c.Write([]byte("req"))
		<-got
		clk.Advance(40 * ms_)
		close(reply)
		if _, err := c.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if l := snapMember(g, "a").Latency; !near(l, 47*ms_) { // 0.3*40 + 0.7*50
			t.Fatalf("EWMA = %v, want 47ms", l)
		}
		clk.Advance(5 * time.Second) // no late timeout after success
		if s := snapMember(g, "a"); s.Failures != 0 {
			t.Fatalf("failures %d", s.Failures)
		}
	})
	t.Run("zero bytes then close is a failure", func(t *testing.T) {
		g, _, a, _ := smartPair(t)
		c, peer := dialPeer(t, g, a)
		defer c.Close()
		go func() { buf := make([]byte, 64); peer.Read(buf); peer.Close() }()
		c.Write([]byte("req"))
		if _, err := c.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("caller must see the original error, got %v", err)
		}
		if s := snapMember(g, "a"); s.Failures != 1 || s.Penalty != 300*ms_ {
			t.Fatalf("snapshot %+v", s)
		}
		if g.Current() != "b" {
			t.Fatalf("current %q", g.Current())
		}
	})
	t.Run("write error before any reply is a failure", func(t *testing.T) {
		g, _, a, _ := smartPair(t)
		c, peer := dialPeer(t, g, a)
		defer c.Close()
		peer.Close()
		if _, err := c.Write([]byte("req")); err == nil {
			t.Fatal("write succeeded")
		}
		if s := snapMember(g, "a"); s.Failures != 1 {
			t.Fatalf("failures %d", s.Failures)
		}
	})
	t.Run("no reply within 3s is a failure", func(t *testing.T) {
		g, clk, a, _ := smartPair(t)
		c, peer := dialPeer(t, g, a)
		defer c.Close()
		defer peer.Close()
		go func() { buf := make([]byte, 64); peer.Read(buf) }()
		c.Write([]byte("req"))
		clk.Advance(2900 * ms_)
		if s := snapMember(g, "a"); s.Failures != 0 {
			t.Fatal("failure before 3s")
		}
		clk.Advance(100 * ms_)
		if s := snapMember(g, "a"); s.Failures != 1 {
			t.Fatalf("no failure after 3s silence: %+v", s)
		}
	})
	t.Run("caller close, caller deadline and server-first are not failures", func(t *testing.T) {
		g, clk, a, _ := smartPair(t)
		// caller closes after writing, before 3s
		c, peer := dialPeer(t, g, a)
		go func() { buf := make([]byte, 64); peer.Read(buf) }()
		c.Write([]byte("req"))
		c.Close()
		peer.Close()
		clk.Advance(10 * time.Second)
		// caller read deadline
		c, peer = dialPeer(t, g, a)
		go func() { buf := make([]byte, 64); peer.Read(buf) }()
		c.Write([]byte("req"))
		c.SetReadDeadline(time.Now().Add(10 * ms_))
		if _, err := c.Read(make([]byte, 1)); !isDeadline(err) {
			t.Fatalf("want deadline error, got %v", err)
		}
		c.Close()
		peer.Close()
		// server speaks first: success without a latency sample
		c, peer = dialPeer(t, g, a)
		go func() { peer.Write([]byte("banner")) }()
		if _, err := c.Read(make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		c.Close()
		peer.Close()
		if s := snapMember(g, "a"); s.Failures != 0 || !near(s.Latency, 50*ms_) {
			t.Fatalf("snapshot %+v", s)
		}
	})
}

func TestSmartUDPNoReplyIsFailure(t *testing.T) {
	g, clk, a, _ := smartPair(t)
	pc, err := g.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := outbound.Addr{Host: "192.0.2.1", Port: 53}
	// reply within 3s: fine
	pc.WriteTo([]byte("q"), dst)
	a.lastPC.in <- []byte("r")
	pc.ReadFrom(make([]byte, 8))
	clk.Advance(4 * time.Second)
	if s := snapMember(g, "a"); s.Failures != 0 {
		t.Fatalf("answered datagram counted as failure")
	}
	// silence for 3s after sending: failure, group moves, session stays on a
	pc.WriteTo([]byte("q"), dst)
	clk.Advance(3 * time.Second)
	if s := snapMember(g, "a"); s.Failures != 1 || s.Penalty == 0 {
		t.Fatalf("UDP silence not counted: %+v", snapMember(g, "a"))
	}
	if g.Current() != "b" {
		t.Fatalf("current %q", g.Current())
	}
	pc.WriteTo([]byte("q"), dst)
	clk.Advance(10 * time.Second) // one failure per silent period
	if s := snapMember(g, "a"); s.Failures != 1 {
		t.Fatalf("failures %d", s.Failures)
	}
	if a.lastPC.sent != 3 {
		t.Fatalf("session migrated: a sent %d", a.lastPC.sent)
	}
	// a reply clears the consecutive count
	a.lastPC.in <- []byte("r")
	pc.ReadFrom(make([]byte, 8))
	if s := snapMember(g, "a"); s.Failures != 0 {
		t.Fatalf("reply did not reset: %+v", s)
	}
}

func TestSmartPausesProbingWhenIdle(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b), clk, p, nil) // interval default 5m
	g.Start(context.Background())
	waitRounds(t, g, 1)
	for k := int64(2); k <= 5; k++ { // t = 5m..20m
		clk.Advance(5 * time.Minute)
		waitRounds(t, g, k)
	}
	clk.Advance(5 * time.Minute) // t = 25m: unused for 5 intervals -> pause
	clk.Advance(2 * time.Hour)
	time.Sleep(20 * ms_)
	if n := g.roundsRun.Load(); n != 5 || isProbing(g) || clk.pending() != 0 {
		t.Fatalf("idle group kept probing: rounds %d probing %v timers %d", n, isProbing(g), clk.pending())
	}
	if p.count("a") != 5 {
		t.Fatalf("probe calls %d", p.count("a"))
	}
	dial(t, g, "x.test") // use resumes probing at once
	waitRounds(t, g, 6)
	clk.Advance(5 * time.Minute)
	waitRounds(t, g, 7)
}
