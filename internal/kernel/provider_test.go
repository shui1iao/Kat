package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

func groupsStart(t *testing.T, c Config) *Server {
	t.Helper()
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	})
	return s
}
func providerURI(name string, port int) string {
	return fmt.Sprintf("socks5://127.0.0.1:%d#%s\n", port, name)
}
func TestProviderHTTPUpdateCacheSelectionAndRaw(t *testing.T) {
	up := groupsStart(t, socksCfg("127.0.0.1:0"))
	port := up.Addresses()[0].(*net.TCPAddr).Port
	var mu sync.Mutex
	body := providerURI("甲", port) + providerURI("乙", port)
	status := 200
	requests := 0
	ua := ""
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		ua = r.UserAgent()
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer sub.Close()
	dir := t.TempDir()
	cache := filepath.Join(dir, "sub.cache")
	cfgfile := filepath.Join(dir, "kat.json")
	c := socksCfg("127.0.0.1:0")
	c.Outbounds = []OutboundConfig{{Name: "fetch", Type: "socks5", Server: "127.0.0.1", Port: uint16(port)}}
	c.Providers = []ProviderConfig{{Name: "p", Type: "http", URL: sub.URL, Path: cache, Interval: Duration(time.Second), Via: "fetch", UserAgent: "Kat-Provider-Acceptance"}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	c.Routing = &RoutingOptions{Final: "pick"}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(cfgfile, b, 0600)
	loaded, e := Load(cfgfile)
	if e != nil {
		t.Fatal(e)
	}
	s := groupsStart(t, loaded)
	s.SetConfigLoader(func() (Config, error) { return Load(cfgfile) })
	waitFor(t, func() bool { return len(s.SelectGroups()[0].Members) == 2 })
	mu.Lock()
	if requests != 1 || ua != "Kat-Provider-Acceptance" {
		t.Error(requests, ua)
	}
	mu.Unlock()
	if up.Stats().Accepted == 0 {
		t.Fatal("subscription did not go through configured fetch outbound")
	}
	if _, e := os.Stat(cache); e != nil {
		t.Fatal(e)
	}
	if e := s.Select("pick", "乙"); e != nil {
		t.Fatal(e)
	}
	target := echoTCP(t)
	conn, ok := socksTo(t, s.Addresses()[0].String(), target)
	if !ok {
		t.Fatal("initial connect")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if !echoOnce(conn, "before") {
		t.Fatal("initial echo")
	}
	gen := s.StatsView().Reload.Generation
	// A half-written user file must not participate in a provider-triggered rebuild.
	os.WriteFile(cfgfile, []byte(`{"inbounds":`), 0600)
	mu.Lock()
	body = providerURI("丙", port) + providerURI("乙", port)
	mu.Unlock()
	waitFor(t, func() bool { return s.StatsView().Reload.Generation > gen })
	sg := s.SelectGroups()[0]
	if sg.Current != "乙" || sg.Source != "runtime" || sg.Default != "" {
		t.Fatalf("first provider changed the configured default: %+v", sg)
	}
	if !echoOnce(conn, "after-update") {
		t.Fatal("established connection broken")
	}
	if s.StatsView().Reload.LiveGenerations < 2 {
		t.Fatal("old active generation not retained")
	}
	c2, ok := socksTo(t, s.Addresses()[0].String(), target)
	if !ok {
		t.Fatal("new connection")
	}
	if !echoOnce(c2, "new-generation") {
		t.Fatal("new echo")
	}
	c2.Close()
	gen = s.StatsView().Reload.Generation
	mu.Lock()
	body = "proxies: []\n"
	mu.Unlock()
	waitFor(t, func() bool { return s.StatsView().Providers[0].Failures >= 1 })
	if s.StatsView().Reload.Generation != gen || len(s.SelectGroups()[0].Members) != 2 {
		t.Fatal("empty result installed")
	}
	mu.Lock()
	status = 503
	mu.Unlock()
	waitFor(t, func() bool { return s.StatsView().Providers[0].Failures >= 2 })
	if !echoOnce(conn, "after-failure") {
		t.Fatal("failure broke connection")
	}
	mu.Lock()
	status = 200
	body = providerURI("丙", port)
	mu.Unlock()
	waitFor(t, func() bool { return len(s.SelectGroups()[0].Members) == 1 })
	if v := s.SelectGroups()[0]; v.Current != "丙" || v.Source != "config" {
		t.Fatal("removed runtime member not restored", v)
	}
	conn.Close()
	waitFor(t, func() bool { return s.StatsView().Reload.LiveGenerations == 1 })
	// Fresh cache starts with nodes and waits until expiry rather than fetching immediately.
	pc := c.Providers[0]
	pc.Interval = Duration(time.Hour)
	c.Providers = []ProviderConfig{pc}
	c.raw = nil
	mu.Lock()
	before := requests
	mu.Unlock()
	cached := groupsStart(t, c)
	if len(cached.SelectGroups()[0].Members) != 1 || cached.StatsView().Providers[0].Source != "cache" {
		t.Fatal("cache not used")
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if requests != before {
		t.Error("fresh cache refetched")
	}
	mu.Unlock()
	t.Logf("HTTP fetch via SOCKS, UA, cache, empty/503 keep-old, raw snapshot, runtime selection and old connections passed; generation=%d", s.StatsView().Reload.Generation)
}
func TestProviderFileExpansionFiltersAndReports(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nodes.yaml")
	os.WriteFile(p, []byte("proxies:\n  - {name: 香港 1, type: socks5, server: 127.0.0.1, port: 9, udp: true}\n  - {name: 香港过期, type: socks5, server: 127.0.0.1, port: 9}\n  - {name: 香港 1, type: anytls, server: 127.0.0.1, port: 9, password: fixture, client-fingerprint: chrome, tfo: true}\n  - {name: unsupported, type: vmess}\n"), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: p}}
	c.Outbounds = []OutboundConfig{{Name: "written", Type: "socks5", Server: "127.0.0.1", Port: 9}, {Name: "香港 1", Type: "socks5", Server: "127.0.0.1", Port: 9}}
	// Written names keep the existing alphabet. Use a valid explicit outbound as the filter exception.
	c.Outbounds = c.Outbounds[:1]
	c.Groups = []GroupConfig{{Name: "filtered", Type: "select", Members: []string{"written"}, Use: []string{"p"}, Filter: "香港", ExcludeFilter: "过期", ExcludeType: "anytls"}, {Name: "all", Type: "select", IncludeAll: true}, {Name: "proxies", Type: "select", IncludeAllProxies: true}, {Name: "providers", Type: "select", IncludeAllProviders: true}}
	reps, gs, e := CheckProviders(c)
	if e != nil {
		t.Fatal(e)
	}
	if len(reps) != 1 || len(reps[0].Nodes) != 3 || len(reps[0].Skipped) != 1 || len(reps[0].Renamed) != 1 || len(reps[0].Ignored) != 1 || len(reps[0].Fingerprints) != 1 {
		t.Fatalf("report: %+v", reps)
	}
	if gs[0].Members != 2 || gs[1].Members != 4 || gs[2].Members != 1 || gs[3].Members != 3 {
		t.Fatal(gs)
	}
	s := groupsStart(t, c)
	if !reflect.DeepEqual(s.SelectGroups()[0].Members, []string{"written", "香港 1"}) {
		t.Fatal(s.SelectGroups())
	}
	// File without interval is re-read on reload, and empty failure retains old nodes.
	os.WriteFile(p, []byte("proxies: []\n"), 0600)
	s.SetConfigLoader(func() (Config, error) { return c, nil })
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if len(s.SelectGroups()[0].Members) != 2 {
		t.Fatal("file empty dropped old")
	}
	t.Logf("dynamic filters exclude expired/anytls but retain explicit written; reports=%+v groups=%+v", reps, gs)
}
func TestRelayEquivalentViaTCPUDPAndValidation(t *testing.T) {
	target := outbound.Addr{Host: "127.0.0.1", Port: rcEchoTCP(t)}
	udp := outbound.Addr{Host: "127.0.0.1", Port: rcEchoUDP(t)}
	c := socksCfg("127.0.0.1:0")
	names := []string{"a", "b", "c", "d"}
	for _, name := range names {
		up := groupsStart(t, socksCfg("127.0.0.1:0"))
		c.Outbounds = append(c.Outbounds, OutboundConfig{Name: name, Type: "socks5", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port)})
	}
	for n := 1; n <= 4; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c0 := c
			c0.Groups = []GroupConfig{{Name: "relay", Type: group.TypeRelay, Members: names[:n]}}
			s := groupsStart(t, c0)
			r := s.rt.nodes["relay"]
			if e := rcTCPEcho(r, target); e != nil {
				t.Fatal(e)
			}
			pc, e := r.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if e = rcUDPEcho(pc, udp); e != nil {
				t.Fatal(e)
			}
			pc.Close()
			v := c
			v.Outbounds = append([]OutboundConfig(nil), c.Outbounds...)
			for i := 1; i < n; i++ {
				v.Outbounds[i].Via = names[i-1]
			}
			sv := groupsStart(t, v)
			ob := sv.rt.nodes[names[n-1]]
			if e := rcTCPEcho(ob, target); e != nil {
				t.Fatal(e)
			}
			pv, e := ob.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if e = rcUDPEcho(pv, udp); e != nil {
				t.Fatal(e)
			}
			pv.Close()
			t.Logf("relay/via %d hops TCP+UDP identical success", n)
		})
	}
	for label, mut := range map[string]func(*Config){"too deep": func(c *Config) {
		c.Outbounds[0].Via = "b"
		c.Groups = []GroupConfig{{Name: "r", Type: group.TypeRelay, Members: []string{"a", "c", "d", "b"}}}
	}, "cycle": func(c *Config) {
		c.Outbounds[0].Via = "r"
		c.Groups = []GroupConfig{{Name: "r", Type: group.TypeRelay, Members: []string{"a", "b"}}}
	}, "illegal member": func(c *Config) {
		c.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"a"}}, {Name: "r", Type: "relay", Members: []string{"a", "g"}}}
	}, "subsequent via": func(c *Config) {
		c.Outbounds[1].Via = "a"
		c.Groups = []GroupConfig{{Name: "r", Type: "relay", Members: []string{"a", "b"}}}
	}} {
		x := c
		x.Outbounds = append([]OutboundConfig(nil), c.Outbounds...)
		mut(&x)
		e := x.Validate()
		if e == nil {
			t.Fatal(label, "accepted")
		}
		if label == "too deep" && !strings.Contains(e.Error(), "deeper than 4") {
			t.Fatal(e)
		}
		t.Log(label, e)
	}
}

func TestLoadBalanceKernelUDPStatistics(t *testing.T) {
	// Different literal loopback IPs are distinct destination keys, even at the same port.
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer probe.Close()
	a := rcEchoUDP(t)
	b := rcEchoUDP(t)
	c := socksCfg("127.0.0.1:0")
	for _, name := range []string{"one", "two"} {
		up := groupsStart(t, socksCfg("127.0.0.1:0"))
		c.Outbounds = append(c.Outbounds, OutboundConfig{Name: name, Type: "socks5", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port)})
	}
	c.Groups = []GroupConfig{{Name: "lb", Type: "load-balance", Members: []string{"one", "two"}, Strategy: "round-robin", Probe: &group.ProbeOptions{URL: probe.URL}}}
	c.Routing = &RoutingOptions{Final: "lb"}
	s := groupsStart(t, c)
	control, u, relay := socksAssociate(t, s, 0)
	defer control.Close()
	defer u.Close()
	// Echo b listens only on .1, so use a fresh .2 echo listener.
	_ = b
	echo2, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if e != nil {
		t.Fatal(e)
	}
	defer echo2.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, e := echo2.ReadFromUDP(buf)
			if e != nil {
				return
			}
			echo2.WriteToUDP(buf[:n], src)
		}
	}()
	dsts := []Address{{"127.0.0.1", a}, {"127.0.0.2", uint16(echo2.LocalAddr().(*net.UDPAddr).Port)}}
	for k, dst := range dsts {
		for i := 0; i < 5; i++ {
			p := []byte(strings.Repeat("x", 100*(k+1)))
			socksUDPSend(t, u, relay, dst, p, 0)
			got := socksUDPRead(t, u)
			if len(got) != len(p) {
				t.Fatal("UDP payload", len(got))
			}
		}
	}
	waitFor(t, func() bool { return s.reg.Total.Load().Down == 1500 })
	for _, v := range s.StatsView().Cumulative.Outbounds {
		if v.Name == "one" && (v.Up != 500 || v.Down != 500) {
			t.Fatal(v)
		}
		if v.Name == "two" && (v.Up != 1000 || v.Down != 1000) {
			t.Fatal(v)
		}
	}
	t.Log("LB UDP two target keys: one=500/500, two=1000/1000, total=1500/1500")
}

func TestProviderSelectPersistenceRestartAndDefaultChange(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "nodes.txt")
	os.WriteFile(file, []byte(providerURI("a", 9)+providerURI("b", 9)), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Stats = &StatsOptions{File: filepath.Join(dir, "x.stats.json")}
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: file}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	s := groupsStart(t, c)
	if e := s.Select("pick", "b"); e != nil {
		t.Fatal(e)
	}
	closeNow(t, s)
	os.WriteFile(file, []byte(providerURI("c", 9)+providerURI("b", 9)), 0600)
	s2 := groupsStart(t, c)
	v := s2.SelectGroups()[0]
	if v.Current != "b" || v.Source != "runtime" || v.Default != "" {
		t.Fatal("provider first-node change reset persisted choice", v)
	}
	closeNow(t, s2)
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}, Selected: "c"}}
	s3 := groupsStart(t, c)
	v = s3.SelectGroups()[0]
	if v.Current != "c" || v.Source != "config" || v.Default != "c" {
		t.Fatal("explicit default change not respected", v)
	}
	t.Log("persisted dynamic select survives provider first-node change across restart; explicit configured default still wins")
}
func TestLoadBalanceRealTCPDistribution(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer probe.Close()
	c := socksCfg("127.0.0.1:0")
	for _, name := range []string{"a", "b", "c"} {
		up := groupsStart(t, socksCfg("127.0.0.1:0"))
		c.Outbounds = append(c.Outbounds, OutboundConfig{Name: name, Type: "socks5", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port)})
	}
	c.Groups = []GroupConfig{{Name: "rr", Type: "load-balance", Members: []string{"a", "b", "c"}, Strategy: "round-robin", Probe: &group.ProbeOptions{URL: probe.URL}}}
	c.Routing = &RoutingOptions{Final: "rr"}
	s := groupsStart(t, c)
	target := echoTCP(t)
	for i := 0; i < 300; i++ {
		conn, ok := socksTo(t, s.Addresses()[0].String(), target)
		if !ok {
			t.Fatal("connect", i)
		}
		if !echoOnce(conn, strings.Repeat("x", 100)) {
			t.Fatal("echo", i)
		}
		conn.Close()
	}
	waitFor(t, func() bool { return s.StatsView().Connections.TCP == 0 })
	for _, v := range s.StatsView().Cumulative.Outbounds {
		if v.Name == "a" || v.Name == "b" || v.Name == "c" {
			if v.Up != 10000 || v.Down != 10000 {
				t.Fatal(v)
			}
		}
	}
	t.Log("300 real SOCKS -> LB -> upstream SOCKS TCP connections: 100 per member, exactly 10000/10000 payload bytes per member")
}

func TestProviderAllUnsupportedStillReported(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nodes.yaml")
	os.WriteFile(file, []byte("proxies:\n - {name: unsupported-vmess, type: vmess}\n - {name: unsupported-plugin, type: ss, plugin: obfs}\n"), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: file}}
	c.Groups = []GroupConfig{{Name: "g", Type: "select", Use: []string{"p"}}}
	reps, _, e := CheckProviders(c)
	if e != nil || len(reps) != 1 || len(reps[0].Skipped) != 2 || reps[0].Error != "no usable node" {
		t.Fatal(reps, e)
	}
	s := groupsStart(t, c)
	if len(s.SelectGroups()[0].Members) != 0 {
		t.Fatal("unsupported nodes installed")
	}
	t.Logf("all unsupported: error=%q individual skipped=%+v", reps[0].Error, reps[0].Skipped)
}

func TestProviderDefaultFetchAndTimedFile(t *testing.T) {
	var mu sync.Mutex
	ua := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ua = r.UserAgent()
		mu.Unlock()
		fmt.Fprint(w, providerURI("default", 9))
	}))
	defer srv.Close()
	s0 := groupsStart(t, socksCfg("127.0.0.1:0"))
	p := newProviderRT(s0.core, ProviderConfig{Name: "p", Type: "http", URL: srv.URL}, filepath.Join(t.TempDir(), "instance.stats.json"))
	body, e := p.fetch(context.Background())
	if e != nil || string(body) != providerURI("default", 9) {
		t.Fatal(string(body), e)
	}
	mu.Lock()
	gotUA := ua
	mu.Unlock()
	if gotUA != "clash.meta" || p.interval() != time.Hour || !strings.Contains(p.cache, "instance.providers/p-") {
		t.Fatal(gotUA, p.interval(), p.cache)
	}
	file := filepath.Join(t.TempDir(), "nodes.txt")
	os.WriteFile(file, []byte(providerURI("a", 9)), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Inbounds = append(c.Inbounds, Inbound{Protocol: "anytls", Listen: "127.0.0.1:0", AnyTLS: &AnyTLSOptions{Password: "provider-certificate-fixture"}})
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: file, Interval: Duration(time.Second)}}
	c.Groups = []GroupConfig{{Name: "g", Type: "select", Use: []string{"p"}}}
	s := groupsStart(t, c)
	old := s.current()
	cert := old.cfg.Inbounds[1].tlsConfig
	os.WriteFile(file, []byte(providerURI("b", 9)), 0600)
	waitFor(t, func() bool { return s.SelectGroups()[0].Current == "b" })
	cur := s.current()
	if &old.cfg.Inbounds[1] == &cur.cfg.Inbounds[1] {
		t.Fatal("inbound Config reused")
	}
	if cur.cfg.Inbounds[1].tlsConfig != cert || !cur.cfg.Inbounds[1].ephemeralTLS {
		t.Fatal("provider rebuild rotated ephemeral certificate")
	}
	t.Log("default direct HTTP fetch UA=clash.meta; interval=1h/cache default; timed file update rebuilt from raw with fresh Inbound storage and preserved AnyTLS ephemeral certificate")
}
