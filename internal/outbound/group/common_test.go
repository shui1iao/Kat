package group

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

var autoTypes = []string{TypeURLTest, TypeFallback, TypeSmart}

func listenLoop(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

func addrOf(ln net.Listener) outbound.Addr {
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return outbound.Addr{Host: ap.Addr().String(), Port: ap.Port()}
}

// ---- failover (criterion 5) ----

func TestRetryNextMemberOnDialError(t *testing.T) {
	for _, typ := range autoTypes {
		a, b := newFake("a"), newFake("b")
		a.setErr(errors.New("handshake failed"))
		g := newAuto(t, Options{Type: typ}, members(a, b), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
		if got := dial(t, g, "x.test"); got != "b" {
			t.Fatalf("%s: dial via %q, want b", typ, got)
		}
		if a.dialCount() != 1 || b.dialCount() != 1 {
			t.Fatalf("%s: dials a=%d b=%d", typ, a.dialCount(), b.dialCount())
		}
	}
}

func TestRetryAtMostThreeMembers(t *testing.T) {
	for _, typ := range autoTypes {
		var fs []outbound.Outbound
		var fakes []*fakeOut
		for _, n := range []string{"a", "b", "c", "d", "e"} {
			f := newFake(n)
			f.setErr(errors.New(n + " down"))
			fs, fakes = append(fs, f), append(fakes, f)
		}
		g := newAuto(t, Options{Type: typ}, fs, newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
		_, err := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 80})
		if err == nil {
			t.Fatalf("%s: dial succeeded", typ)
		}
		total := 0
		for _, f := range fakes {
			total += f.dialCount()
		}
		if total != 3 {
			t.Fatalf("%s: %d dial attempts, want 3 (err %v)", typ, total, err)
		}
		if !strings.Contains(err.Error(), "3 member(s) failed") {
			t.Fatalf("%s: err %v", typ, err)
		}
	}
}

func TestRetryStopsAtContextDeadline(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	a.onDial = func(ctx context.Context, _ outbound.Addr) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*ms_)
	defer cancel()
	if _, err := g.DialTCP(ctx, outbound.Addr{Host: "x.test", Port: 80}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if b.dialCount() != 0 {
		t.Fatal("tried another member after the context expired")
	}
}

func TestNoRetryAfterDataWritten(t *testing.T) {
	for _, typ := range autoTypes {
		a, b := newFake("a"), newFake("b")
		g := newAuto(t, Options{Type: typ}, members(a, b), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
		c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 80})
		if err != nil {
			t.Fatal(err)
		}
		peer := <-a.peers
		go func() { buf := make([]byte, 64); peer.Read(buf); peer.Close() }()
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(make([]byte, 16)); err != io.EOF {
			t.Fatalf("%s: caller got %v, want the member's EOF", typ, err)
		}
		c.Close()
		if b.dialCount() != 0 {
			t.Fatalf("%s: data was replayed on another member", typ)
		}
	}
}

// ---- nesting and UDP (criterion 6) ----

func TestNestedGroup(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	target := netip.MustParseAddrPort(srv.Listener.Addr().String())

	x, y := &loopOut{name: "x"}, &loopOut{name: "y"}
	inner, err := New(Options{Name: "inner", Type: TypeSelect, Members: []string{"x", "y"}, Selected: "y"}, members(x, y), nil)
	if err != nil {
		t.Fatal(err)
	}
	slow := &loopOut{name: "slow", delay: 300 * ms_}
	outer, err := New(Options{Name: "outer", Type: TypeURLTest, Members: []string{"slow", "inner"},
		Probe: &ProbeOptions{URL: srv.URL + "/generate_204"}}, members(slow, inner), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	outer.Start(context.Background())
	og := outer.(*autoGroup)
	if dialAddr(t, outer, target) != nil { // first use (slow, first member) + background probe
		t.Fatal("first dial failed")
	}
	waitRounds(t, og, 1)
	if outer.Current() != "inner" {
		t.Fatalf("outer current %q (snapshot %+v)", outer.Current(), og.Snapshot())
	}
	// the probe through the nested group went through its current member y only
	if len(x.targets()) != 0 {
		t.Fatalf("probe used inner non-selected member x: %v", x.targets())
	}
	want := outbound.Addr{Host: target.Addr().String(), Port: target.Port()}
	for _, d := range append(y.targets(), slow.targets()...) {
		if d != want {
			t.Fatalf("dialed %v, only the probe URL %v is allowed", d, want)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("probe requests %d, want one per member", hits.Load())
	}
	n := len(y.targets())
	if dialAddr(t, outer, target) != nil || len(y.targets()) != n+1 {
		t.Fatal("outer dial did not go through inner's selected member")
	}
	// inner select switch is visible to the outer group
	inner.(Selector).Select("x")
	if dialAddr(t, outer, target) != nil || len(x.targets()) != 1 {
		t.Fatal("outer dial did not follow inner selection")
	}
}

func dialAddr(t *testing.T, d outbound.Dialer, ap netip.AddrPort) error {
	c, err := d.DialTCP(context.Background(), outbound.Addr{Host: ap.Addr().String(), Port: ap.Port()})
	if err == nil {
		c.Close()
	}
	return err
}

func TestUDPMemberFilter(t *testing.T) {
	for _, typ := range autoTypes {
		a, b, c := newFake("a"), newFake("b"), newFake("c")
		a.udp = false
		g := newAuto(t, Options{Type: typ}, members(a, b, c), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
		if g.Current() != "a" || !g.UDP() {
			t.Fatalf("%s: current %q udp %v", typ, g.Current(), g.UDP())
		}
		pc, err := g.ListenPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		pc.Close()
		if a.lps != 0 || b.lps != 1 {
			t.Fatalf("%s: ListenPacket a=%d b=%d (a has no UDP)", typ, a.lps, b.lps)
		}
		b.lpErr = errors.New("udp setup failed") // retried on the next UDP member
		pc, err = g.ListenPacket(context.Background())
		if err != nil || c.lps != 1 {
			t.Fatalf("%s: retry: %v c=%d", typ, err, c.lps)
		}
		pc.Close()

		n1, n2 := newFake("n1"), newFake("n2")
		n1.udp, n2.udp = false, false
		g2 := newAuto(t, Options{Type: typ}, members(n1, n2), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
		if g2.UDP() {
			t.Fatalf("%s: UDP() true without UDP members", typ)
		}
		if _, err := g2.ListenPacket(context.Background()); !errors.Is(err, outbound.ErrNoMember) {
			t.Fatalf("%s: err %v, want ErrNoMember", typ, err)
		}
		if n1.lps+n2.lps != 0 {
			t.Fatalf("%s: non-UDP member asked for a PacketConn", typ)
		}
	}
	// select: only its selected member
	a, b := newFake("a"), newFake("b")
	a.udp = false
	s, _ := New(Options{Name: "s", Type: TypeSelect, Members: []string{"a", "b"}}, members(a, b), nil)
	if _, err := s.ListenPacket(context.Background()); !errors.Is(err, outbound.ErrNoMember) || b.lps != 0 {
		t.Fatalf("select non-UDP selected: %v", err)
	}
	s.(Selector).Select("b")
	if pc, err := s.ListenPacket(context.Background()); err != nil || b.lps != 1 {
		t.Fatalf("select UDP: %v", err)
	} else {
		pc.Close()
	}
}

// ---- lifecycle (criterion 7) ----

func TestStartCloseNoGoroutineLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	ln := listenLoop(t)
	time.Sleep(20 * ms_)
	base := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	var gs []Group
	for i, typ := range append(autoTypes, TypeSelect) {
		a, b := &loopOut{name: "a"}, &loopOut{name: "b", delay: 5 * ms_}
		o := Options{Name: "g", Type: typ, Members: []string{"a", "b"}}
		if typ != TypeSelect {
			o.Probe = &ProbeOptions{URL: srv.URL + "/", Interval: outbound.Duration(time.Second), Timeout: outbound.Duration(2 * time.Second)}
		}
		g, err := New(o, members(a, b), nil)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			g.Start(ctx) // stopped by ctx
		} else {
			g.Start(context.Background()) // stopped by Close
		}
		for j := 0; j < 3; j++ {
			c, err := g.DialTCP(context.Background(), addrOf(ln))
			if err != nil {
				t.Fatal(err)
			}
			c.Write([]byte("ping"))
			c.Read(make([]byte, 4))
			c.Close()
		}
		gs = append(gs, g)
	}
	time.Sleep(1500 * ms_) // let smart run a periodic round as well
	cancel()
	for _, g := range gs {
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		g.Close() // idempotent
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines %d > baseline %d\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * ms_)
	}
	t.Logf("goroutines back to baseline %d", base)
}

func TestContextCancelStopsProbing(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 10 * ms_, "b": 20 * ms_})
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b), clk, p, nil)
	ctx, cancel := context.WithCancel(context.Background())
	g.Start(ctx)
	waitRounds(t, g, 1)
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for clk.pending() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	clk.Advance(time.Hour)
	dial(t, g, "x.test")
	time.Sleep(20 * ms_)
	if g.roundsRun.Load() != 1 || clk.pending() != 0 {
		t.Fatalf("probing continued after ctx cancel: rounds %d timers %d", g.roundsRun.Load(), clk.pending())
	}
}

// ---- HTTP(S) prober ----

func TestHTTPProber(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(204)
		case "/404":
			w.WriteHeader(404)
		case "/302":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/503":
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	target := outbound.Addr{Host: ap.Addr().String(), Port: ap.Port()}
	m := &loopOut{name: "m", delay: 60 * ms_}
	for _, tc := range []struct {
		path string
		ok   bool
	}{{"/204", true}, {"/404", true}, {"/302", true}, {"/503", false}} {
		p := &httpProber{url: srv.URL + tc.path, target: target, clk: realClock{}}
		lat, err := p.probe(context.Background(), m)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err %v", tc.path, err)
		}
		if tc.ok && lat < 60*ms_ {
			t.Fatalf("%s: latency %v does not include the member dial (60ms)", tc.path, lat)
		}
		t.Logf("%s: latency %v err %v", tc.path, lat, err)
	}
	mu.Lock()
	got := strings.Join(paths, ",")
	mu.Unlock()
	if got != "GET /204,GET /404,GET /302,GET /503" {
		t.Fatalf("requests %q (redirect must not be followed)", got)
	}
	for _, d := range m.targets() {
		if d != target {
			t.Fatalf("dialed %v", d)
		}
	}
	// timeout
	slow := &loopOut{name: "slow", delay: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 50*ms_)
	defer cancel()
	if _, err := (&httpProber{url: srv.URL + "/204", target: target, clk: realClock{}}).probe(ctx, slow); err == nil {
		t.Fatal("probe ignored timeout")
	}
	// member failure
	if _, err := (&httpProber{url: srv.URL + "/204", target: target, clk: realClock{}}).probe(context.Background(), &loopOut{name: "f", fail: true}); err == nil {
		t.Fatal("probe through failing member succeeded")
	}
}

func TestHTTPSProberVerifiesCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	target := outbound.Addr{Host: ap.Addr().String(), Port: ap.Port()}
	m := &loopOut{name: "m"}
	p := &httpProber{url: srv.URL + "/", target: target, clk: realClock{}}
	_, err := p.probe(context.Background(), m)
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &ua) {
		t.Fatalf("untrusted certificate: err %v, want x509.UnknownAuthorityError", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p.tls = &tls.Config{RootCAs: pool}
	if _, err := p.probe(context.Background(), m); err != nil {
		t.Fatalf("trusted certificate: %v", err)
	}
	// through New/hooks: the group probes https via the member
	g, err := newGroup(Options{Name: "g", Type: TypeURLTest, Members: []string{"m"}, Probe: &ProbeOptions{URL: srv.URL + "/"}},
		members(m), nil, hooks{tls: &tls.Config{RootCAs: pool}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Start(context.Background())
	dialAddr(t, g, ap)
	ag := g.(*autoGroup)
	waitRounds(t, ag, 1)
	if s := snapMember(ag, "m"); !s.ProbeOK || s.ProbeLatency <= 0 {
		t.Fatalf("snapshot %+v", s)
	}
}

func TestProbeRoundConcurrencyLimit(t *testing.T) {
	var cur, peak atomic.Int32
	var mu sync.Mutex
	calls := map[string]int{}
	probe := func(ctx context.Context, m outbound.Outbound) (time.Duration, error) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * ms_)
		cur.Add(-1)
		mu.Lock()
		calls[m.Name()]++
		mu.Unlock()
		return 10 * ms_, nil
	}
	var fs []outbound.Outbound
	for _, n := range []string{"m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9"} {
		fs = append(fs, newFake(n))
	}
	g, err := newGroup(Options{Name: "g", Type: TypeSmart, Members: names(fs), Probe: probeOpts()}, fs, nil, hooks{clk: newFakeClock(), probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Start(context.Background())
	waitRounds(t, g.(*autoGroup), 1)
	if peak.Load() > probeConcurrency || peak.Load() < 2 {
		t.Fatalf("peak concurrency %d", peak.Load())
	}
	for _, f := range fs {
		if calls[f.Name()] != 1 {
			t.Fatalf("member %s probed %d times in one round (%v)", f.Name(), calls[f.Name()], sortedKeys(calls))
		}
	}
	t.Logf("peak concurrent probes: %d", peak.Load())
}

// ---- connection wrapper transparency ----

func TestConnWrapperTransparent(t *testing.T) {
	ln := listenLoop(t)
	direct := &loopOut{name: "direct"}
	pipeOnly := newFake("p")
	g := newAuto(t, Options{Type: TypeSmart, Members: []string{"direct", "p"}}, members(direct, pipeOnly), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
	c, err := g.DialTCP(context.Background(), addrOf(ln))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T hides CloseWrite of *net.TCPConn", c)
	}
	if c.LocalAddr() == nil || c.RemoteAddr().String() != ln.Addr().String() {
		t.Fatal("addresses not passed through")
	}
	if _, err := c.Write([]byte("echo me")); err != nil {
		t.Fatal(err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(c) // echo server closes after our half-close
	if err != nil || string(all) != "echo me" {
		t.Fatalf("got %q %v", all, err)
	}
	// a conn without CloseWrite must not grow one
	g2 := newAuto(t, Options{Type: TypeSmart, Members: []string{"p"}}, members(pipeOnly), newFakeClock(), newFakeProbe(map[string]time.Duration{}), nil)
	c2, err := g2.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, ok := c2.(interface{ CloseWrite() error }); ok {
		t.Fatal("wrapper invented CloseWrite")
	}
	// deadlines reach the inner conn
	if err := c2.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Read(make([]byte, 1)); !isDeadline(err) {
		t.Fatalf("read deadline not passed through: %v", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	peer := <-pipeOnly.peers
	go peer.Write([]byte("z"))
	if n, err := c2.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("read after clearing deadline: %d %v", n, err)
	}
	if err := c2.Close(); err != nil {
		t.Fatal(err)
	}
	peer.Close()
}

// ---- validation ----

func TestValidate(t *testing.T) {
	p := probeOpts()
	ok := []Options{
		{Name: "s", Type: TypeSelect, Members: []string{"a", "direct", "reject"}, Selected: "reject"},
		{Name: "u", Type: TypeURLTest, Members: []string{"a", "direct"}, Probe: p, Tolerance: outbound.Duration(0)},
		{Name: "f", Type: TypeFallback, Members: []string{"a"}, Probe: &ProbeOptions{URL: "https://[2001:db8::1]:8443/x", Interval: outbound.Duration(time.Minute), Timeout: outbound.Duration(60 * time.Second)}},
		{Name: "m", Type: TypeSmart, Members: []string{"a", "b"}, Probe: p, Priority: map[string]float64{"a": 0.5, "b": 100}},
	}
	for _, o := range ok {
		if err := Validate(o); err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	many := make([]string, 65)
	for i := range many {
		many[i] = "m" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	bad := map[string]Options{
		"no name":             {Type: TypeSelect, Members: []string{"a"}},
		"bad type":            {Name: "g", Type: "load-balance", Members: []string{"a"}},
		"no members":          {Name: "g", Type: TypeSelect},
		"65 members":          {Name: "g", Type: TypeSelect, Members: many},
		"dup member":          {Name: "g", Type: TypeSelect, Members: []string{"a", "a"}},
		"self member":         {Name: "g", Type: TypeSelect, Members: []string{"g"}},
		"selected not member": {Name: "g", Type: TypeSelect, Members: []string{"a"}, Selected: "b"},
		"select with probe":   {Name: "g", Type: TypeSelect, Members: []string{"a"}, Probe: p},
		"selected on auto":    {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: p, Selected: "a"},
		"auto without probe":  {Name: "g", Type: TypeSmart, Members: []string{"a"}},
		"probe no url":        {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{}},
		"probe ftp":           {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{URL: "ftp://x/"}},
		"probe relative":      {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{URL: "/generate_204"}},
		"probe port 0":        {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{URL: "http://x:0/"}},
		"timeout > 60s":       {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{URL: "http://x/", Timeout: outbound.Duration(61 * time.Second)}},
		"negative interval":   {Name: "g", Type: TypeURLTest, Members: []string{"a"}, Probe: &ProbeOptions{URL: "http://x/", Interval: outbound.Duration(-time.Second)}},
		"tolerance on smart":  {Name: "g", Type: TypeSmart, Members: []string{"a"}, Probe: p, Tolerance: outbound.Duration(time.Second)},
		"priority on fb":      {Name: "g", Type: TypeFallback, Members: []string{"a"}, Probe: p, Priority: map[string]float64{"a": 1}},
		"priority unknown":    {Name: "g", Type: TypeSmart, Members: []string{"a"}, Probe: p, Priority: map[string]float64{"b": 1}},
		"priority zero":       {Name: "g", Type: TypeSmart, Members: []string{"a"}, Probe: p, Priority: map[string]float64{"a": 0}},
		"priority > 100":      {Name: "g", Type: TypeSmart, Members: []string{"a"}, Probe: p, Priority: map[string]float64{"a": 101}},
		"reject in auto":      {Name: "g", Type: TypeFallback, Members: []string{"a", "reject"}, Probe: p},
	}
	for name, o := range bad {
		if err := Validate(o); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// JSON shape of a documented url-test group
	var o Options
	js := `{"name":"auto","type":"url-test","members":["jp","us"],"probe":{"url":"https://www.example.com/generate_204","interval":"10m","timeout":"5s"},"tolerance":"100ms"}`
	if err := json.Unmarshal([]byte(js), &o); err != nil || Validate(o) != nil || o.Probe.Interval.Value() != 10*time.Minute {
		t.Fatalf("json: %+v %v", o, err)
	}
	// New checks member wiring
	a := newFake("a")
	if _, err := New(Options{Name: "g", Type: TypeSelect, Members: []string{"a", "b"}}, members(a), nil); err == nil {
		t.Fatal("New accepted missing member")
	}
	if _, err := New(Options{Name: "g", Type: TypeSelect, Members: []string{"b"}}, members(a), nil); err == nil {
		t.Fatal("New accepted wrong member name")
	}
}

func TestDefaultsApplied(t *testing.T) {
	for typ, want := range map[string]time.Duration{TypeURLTest: 10 * time.Minute, TypeFallback: 10 * time.Minute, TypeSmart: 5 * time.Minute} {
		c, err := normalize(Options{Name: "g", Type: typ, Members: []string{"a"}, Probe: probeOpts()})
		if err != nil || c.interval != want || c.timeout != 5*time.Second {
			t.Fatalf("%s: %+v %v", typ, c, err)
		}
		if typ == TypeURLTest && c.tolerance != 100*time.Millisecond {
			t.Fatalf("tolerance default %v", c.tolerance)
		}
		if typ == TypeSmart && c.priority[0] != 1 {
			t.Fatalf("priority default %v", c.priority)
		}
	}
}

func TestSnapshotHasNoDestinations(t *testing.T) {
	g, _, a, _ := smartPair(t)
	c, peer := dialPeer(t, g, a)
	go func() { buf := make([]byte, 8); peer.Read(buf); peer.Write([]byte("ok")) }()
	c.Write([]byte("x"))
	c.Read(make([]byte, 2))
	c.Close()
	js, _ := json.Marshal(g.Snapshot())
	if strings.Contains(string(js), "t.test") {
		t.Fatalf("snapshot leaks destination: %s", js)
	}
}
