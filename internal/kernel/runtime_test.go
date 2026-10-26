package kernel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// socksConnect opens a SOCKS5 CONNECT through s and returns the reply code.
func socksConnect(t *testing.T, s *Server, a Address) (net.Conn, byte) {
	t.Helper()
	c := dialPeer(t, s, nil)
	socksGreeting(t, c, false, "")
	if e := writeAll(c, peerHeader("socks5", 1, a)); e != nil {
		t.Fatal(e)
	}
	h, e := readN(c, 3)
	if e != nil {
		return c, 0xff
	}
	if _, e := readAddress(c, false); e != nil {
		t.Fatal(e)
	}
	return c, h[1]
}

func TestBlockedDestinationTable(t *testing.T) {
	def := Config{}
	allow := Config{Security: &SecurityOptions{AllowLoopback: true}}
	priv := Config{Security: &SecurityOptions{BlockPrivate: true}}
	for _, tc := range []struct {
		ip                  string
		def, allowed, block bool
	}{
		{"127.0.0.1", true, false, true},
		{"127.1.2.3", true, false, true},
		{"::1", true, false, true},
		{"::ffff:127.0.0.1", true, false, true},
		{"0.0.0.0", true, false, true},
		{"0.1.2.3", true, false, true},
		{"::", true, false, true},
		{"::ffff:0.0.0.0", true, false, true},
		{"10.1.2.3", false, false, true},
		{"172.16.0.1", false, false, true},
		{"192.168.1.1", false, false, true},
		{"100.64.0.1", false, false, true},
		{"169.254.1.1", false, false, true},
		{"fd00::1", false, false, true},
		{"fe80::1", false, false, true},
		{"::ffff:192.168.1.1", false, false, true},
		{"1.1.1.1", false, false, false},
		{"2606:4700::1111", false, false, false},
	} {
		ip := netip.MustParseAddr(tc.ip)
		if def.blockedDestination(ip) != tc.def || allow.blockedDestination(ip) != tc.allowed || priv.blockedDestination(ip) != tc.block {
			t.Errorf("%s: default=%v allow=%v private=%v", tc.ip, def.blockedDestination(ip), allow.blockedDestination(ip), priv.blockedDestination(ip))
		}
	}
}

func TestDefaultGuardRefusesLocalTCPAndUDP(t *testing.T) {
	echo := echoTCP(t)
	uecho, _ := echoUDP(t)
	run := func(name string, modify func(*Config)) {
		t.Run(name, func(t *testing.T) {
			s := startTest(t, inFor("socks5", nil), func(c *Config) {
				c.Security = nil // the 0.7.0 default
				if modify != nil {
					modify(c)
				}
			})
			for _, h := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1", "localhost"} {
				c, code := socksConnect(t, s, Address{h, echo.Port})
				if code == 0 {
					t.Errorf("TCP to %s allowed", h)
				}
				c.Close()
			}
			// UDP to a loopback echo gets no answer.
			c, u, relay := socksAssociate(t, s, 0)
			defer c.Close()
			for _, h := range []string{"::1", "localhost", "127.0.0.1"} {
				socksUDPSend(t, u, relay, Address{h, uecho.Port}, []byte("ping"), 0)
			}
			u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			b := make([]byte, 2048)
			if _, _, e := u.ReadFromUDP(b); e == nil {
				t.Error("UDP to loopback answered")
			}
			waitFor(t, func() bool { return s.tcpFlows.Load() <= 1 })
		})
	}
	run("fast path", nil)
	dns := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 60) })
	run("routing engine", func(c *Config) {
		c.DNS = &DNSOptions{Server: "udp://" + dns.udp.LocalAddr().String()}
	})
}

func TestAllowLoopbackAndBlockPrivate(t *testing.T) {
	echo := echoTCP(t)
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.Security = &SecurityOptions{AllowLoopback: true, BlockPrivate: true} })
	c, code := socksConnect(t, s, echo)
	if code != 0 {
		t.Fatal("allow_loopback refused", code)
	}
	c.Close()
	start := time.Now()
	c, code = socksConnect(t, s, Address{"192.168.255.254", 9})
	c.Close()
	if code == 0 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("block_private: code %d after %v", code, time.Since(start))
	}
}

func TestStatsMeteringDetailsAndClose(t *testing.T) {
	echo := echoTCP(t)
	s := startTest(t, inFor("socks5", nil), func(c *Config) {
		c.Stats = &StatsOptions{Connections: true}
		c.Log = &LogOptions{}
	})
	const n = 3<<20 + 12345
	payload := make([]byte, n)
	rand.Read(payload)
	c, code := socksConnect(t, s, echo)
	if code != 0 {
		t.Fatal(code)
	}
	go writeAll(c, payload)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	got, e := readN(c, n)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch", e)
	}
	c2, _ := socksConnect(t, s, echo)
	list := s.connections()
	if len(list) != 2 || list[0].Source != "127.0.0.0/24" || list[0].Target != echo.String() || list[0].Rule != "final->direct" || strings.Join(list[0].Chain, ">") != "direct" || list[0].Network != "tcp" || list[0].Inbound != "socks5/127.0.0.1:0" {
		t.Fatalf("details %+v", list)
	}
	if !s.closeFlow(list[0].ID) {
		t.Fatal("close by id")
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("closed connection still open")
	}
	// The other connection keeps working.
	writeAll(c2, []byte("still"))
	if b, e := readN(c2, 5); e != nil || string(b) != "still" {
		t.Fatal("unrelated connection affected", e)
	}
	waitFor(t, func() bool { return len(s.connections()) == 1 })
	if s.closeAllFlows() != 1 {
		t.Fatal("close all")
	}
	waitFor(t, func() bool { return s.tcpFlows.Load() == 0 && len(s.connections()) == 0 })
	v := s.StatsView()
	cu := v.Cumulative
	if cu.Total.Up != n+5 || cu.Total.Down != n+5 {
		t.Fatalf("total %+v", cu.Total)
	}
	if cu.Inbounds[0].Up != n+5 || cu.Outbounds[0].Name != "direct" || cu.Outbounds[0].Down != n+5 || cu.Rules[0].Name != "final->direct" || cu.Rules[0].Hits != 2 || cu.Rules[0].Up != n+5 {
		t.Fatalf("breakdown %+v", cu)
	}
	if v.Connections.TCP != 0 || v.Connections.UDP != 0 {
		t.Fatalf("connections %+v", v.Connections)
	}
}

func TestUDPStatsAndDetails(t *testing.T) {
	uecho, _ := echoUDP(t)
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.Stats = &StatsOptions{Connections: true} })
	c, u, relay := socksAssociate(t, s, 0)
	for i := 0; i < 5; i++ {
		socksUDPSend(t, u, relay, uecho, bytes.Repeat([]byte{'x'}, 1000), 0)
		if p := socksUDPRead(t, u); len(p) != 1000 {
			t.Fatal(len(p))
		}
	}
	waitFor(t, func() bool { return s.reg.Total.Load().Down == 5000 })
	list := s.connections()
	if len(list) != 2 { // the SOCKS control connection is not a flow; the association is
		if len(list) != 1 {
			t.Fatalf("details %+v", list)
		}
	}
	var assoc ConnInfo
	for _, x := range list {
		if x.Network == "udp" {
			assoc = x
		}
	}
	if assoc.Up != 5000 || assoc.Down != 5000 || assoc.Target != uecho.String() || assoc.Source != "127.0.0.0/24" {
		t.Fatalf("udp details %+v", list)
	}
	if v := s.StatsView(); v.Connections.UDP != 1 || v.Cumulative.Rules[0].Hits != 1 {
		t.Fatalf("view %+v", v)
	}
	c.Close()
	waitFor(t, func() bool { return s.StatsView().Connections.UDP == 0 && len(s.connections()) == 0 })
}

func TestAccessLogJSONAndTextPrivacy(t *testing.T) {
	echo := echoTCP(t)
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kat.log")
			s := startTest(t, inFor("socks5", nil), func(c *Config) {
				c.Log = &LogOptions{Format: format, File: path, Access: true, MaxSizeMB: 1, MaxBackups: 1}
			})
			c, code := socksConnect(t, s, Address{"localhost", echo.Port})
			if code != 0 {
				t.Fatal(code)
			}
			writeAll(c, []byte("hello"))
			readN(c, 5)
			c.Close()
			var line string
			waitFor(t, func() bool {
				b, _ := os.ReadFile(path)
				for _, l := range strings.Split(string(b), "\n") {
					if strings.Contains(l, "access") {
						line = l
						return true
					}
				}
				return false
			})
			if format == "json" {
				var m map[string]any
				if e := json.Unmarshal([]byte(line), &m); e != nil {
					t.Fatal(line, e)
				}
				if m["event"] != "access" || m["src"] != "127.0.0.0/24" || m["dst"] != "localhost:"+strconv.Itoa(int(echo.Port)) || m["up"] != float64(5) || m["level"] != "info" || m["chain"] != "direct" {
					t.Fatal(line)
				}
			} else if !strings.Contains(line, " src=127.0.0.0/24 dst=localhost:"+strconv.Itoa(int(echo.Port))+" ") || strings.Contains(line, "src=127.0.0.1") {
				t.Fatal(line)
			}
		})
	}
}

func TestAccessLogOffByDefault(t *testing.T) {
	echo := echoTCP(t)
	var buf bytes.Buffer
	s := startTest(t, inFor("socks5", nil), nil)
	s.log.write = func(p []byte) error { buf.Write(p); return nil }
	c, _ := socksConnect(t, s, echo)
	c.Close()
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(buf.String(), "access") {
		t.Fatal(buf.String())
	}
	if len(s.connections()) != 0 {
		t.Fatal("details kept although disabled")
	}
	if _, ok := (apiBackend{s.core}).Connections(); ok {
		t.Fatal("details API enabled by default")
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	l, _ := newLogger(&LogOptions{Level: "warn"})
	l.write = func(p []byte) error { buf.Write(p); return nil }
	l.emit(levelInfo, []byte("kat event=info_line\n"))
	l.emit(levelWarn, []byte("kat event=warn_line\n"))
	l.setLevel(levelDebug)
	l.emit(levelDebug, []byte("kat event=debug_line\n"))
	if got := buf.String(); got != "kat event=warn_line\nkat event=debug_line\n" {
		t.Fatalf("%q", got)
	}
	for _, bad := range []string{"trace", "INFO2"} {
		if _, ok := parseLevel(bad); ok {
			t.Fatal(bad)
		}
	}
	if (&Config{Log: &LogOptions{Level: "loud"}}).validateRuntime() == nil || (&Config{Log: &LogOptions{Format: "xml"}}).validateRuntime() == nil || (&Config{Log: &LogOptions{File: "rel.log"}}).validateRuntime() == nil {
		t.Fatal("bad log options accepted")
	}
}

func TestDefaultLogUnchanged(t *testing.T) {
	// No "log" block: lines reach the sink byte-for-byte (0.6.3 format).
	l, e := newLogger(nil)
	if e != nil || l.json || l.file != nil || l.access.Load() || l.getLevel() != levelInfo {
		t.Fatal("default logger changed")
	}
	var buf bytes.Buffer
	l.write = func(p []byte) error { buf.Write(p); return nil }
	l.emit(levelWarn, []byte("kat event=failure stage=dial reason=connect_failed protocol=outbound inbound=-1 suppressed=0\n"))
	if buf.String() != "kat event=failure stage=dial reason=connect_failed protocol=outbound inbound=-1 suppressed=0\n" {
		t.Fatalf("%q", buf.String())
	}
}

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	r, e := openRotatingFile(path, 100, 2)
	if e != nil {
		t.Fatal(e)
	}
	line := bytes.Repeat([]byte("a"), 39)
	line = append(line, '\n')
	for i := 0; i < 10; i++ {
		if e := r.Write(line); e != nil {
			t.Fatal(e)
		}
	}
	r.Close()
	for _, p := range []string{path, path + ".1", path + ".2"} {
		st, e := os.Stat(p)
		if e != nil || st.Size() > 100 || st.Mode().Perm() != 0o600 {
			t.Fatal(p, e)
		}
	}
	if _, e := os.Stat(path + ".3"); e == nil {
		t.Fatal("more backups than configured")
	}
}

func TestJSONLine(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := string(jsonLine(now, levelWarn, []byte("kat event=failure stage=dial inbound=-1 suppressed=0 count=12\n")))
	want := `{"time":"2026-01-02T03:04:05Z","level":"warn","event":"failure","stage":"dial","inbound":"-1","suppressed":0,"count":12}` + "\n"
	if got != want {
		t.Fatalf("%s", got)
	}
	got = string(jsonLine(now, levelInfo, []byte("listening 127.0.0.1:1\n")))
	if got != `{"time":"2026-01-02T03:04:05Z","level":"info","msg":"listening 127.0.0.1:1"}`+"\n" {
		t.Fatal(got)
	}
}

func TestTruncateSource(t *testing.T) {
	for in, want := range map[string]string{"203.0.113.77": "203.0.113.0/24", "::ffff:203.0.113.77": "203.0.113.0/24", "2001:db8:1234:5678::1": "2001:db8:1234::/48", "fe80::1%eth0": "fe80::/48"} {
		if got := truncateSource(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
	if truncateSource(netip.Addr{}) != "-" {
		t.Fatal("invalid")
	}
}

func TestRuntimeConfigValidation(t *testing.T) {
	good := "0123456789abcdef"
	for _, a := range []APIOptions{
		{Listen: "0.0.0.0:9090", Secret: good},
		{Listen: "[::]:9090", Secret: good},
		{Listen: "192.168.1.1:9090", Secret: good},
		{Listen: "localhost:9090", Secret: good},
		{Listen: "127.0.0.1:0", Secret: good},
		{Listen: "127.0.0.1:9090"},
		{Listen: "127.0.0.1:9090", Secret: "short"},
		{Secret: good},
		{Socket: "relative.sock"},
	} {
		a := a
		if e := (&Config{API: &a}).validateRuntime(); e == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	for _, a := range []APIOptions{{Listen: "127.0.0.1:9090", Secret: good}, {Listen: "[::1]:9090", Secret: good}, {Listen: "127.0.0.2:1", Secret: good}} {
		a := a
		if e := (&Config{API: &a}).validateRuntime(); e != nil {
			t.Errorf("rejected %+v: %v", a, e)
		}
	}
	for _, st := range []StatsOptions{{SaveInterval: Duration(time.Second)}, {File: "x.json"}} {
		st := st
		if (&Config{Stats: &st}).validateRuntime() == nil {
			t.Errorf("accepted %+v", st)
		}
	}
	// The whole configuration file path: check rejects a public API listener.
	p := writeConfig(t, `{"api":{"listen":"0.0.0.0:9090","secret":"0123456789abcdef"},"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}]}`)
	if _, e := Load(p); e == nil {
		t.Fatal("non-loopback api.listen loaded")
	}
}

// apiClient talks HTTP over the Unix socket.
func unixClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}, Timeout: 5 * time.Second}
}

func freeTCPPort(t *testing.T) int {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestManagementAPI(t *testing.T) {
	dir, e := os.MkdirTemp("", "katapi")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "run", "t.sock")
	listen := "127.0.0.1:" + strconv.Itoa(freeTCPPort(t))
	secret := "0123456789abcdef-test"
	s := startTest(t, inFor("socks5", nil), func(c *Config) {
		c.API = &APIOptions{Socket: sock, Listen: listen, Secret: secret}
		c.Stats = &StatsOptions{Connections: true}
	})
	st, e := os.Stat(sock)
	if e != nil || st.Mode().Perm() != 0o600 || st.Mode()&os.ModeSocket == 0 {
		t.Fatal("socket mode", e)
	}
	if d, _ := os.Stat(filepath.Dir(sock)); d.Mode().Perm() != 0o700 {
		t.Fatal("socket dir mode", d.Mode())
	}
	uc := unixClient(sock)
	r, e := uc.Get("http://kat/v1/stats")
	if e != nil || r.StatusCode != 200 {
		t.Fatal(e)
	}
	var v StatsView
	json.NewDecoder(r.Body).Decode(&v)
	r.Body.Close()
	if !v.Details || len(v.Cumulative.Inbounds) != 1 {
		t.Fatalf("%+v", v)
	}
	// Log level switching.
	req, _ := http.NewRequest("PUT", "http://kat/v1/log/level", strings.NewReader(`{"level":"debug"}`))
	if r, e = uc.Do(req); e != nil || r.StatusCode != 200 || s.log.getLevel() != levelDebug {
		t.Fatal("level", e)
	}
	r.Body.Close()
	req, _ = http.NewRequest("PUT", "http://kat/v1/log/level", strings.NewReader(`{"level":"loud"}`))
	if r, e = uc.Do(req); e != nil || r.StatusCode != 400 || s.log.getLevel() != levelDebug {
		t.Fatal("bad level accepted", e)
	}
	r.Body.Close()
	// Close of an unknown id.
	req, _ = http.NewRequest("DELETE", "http://kat/v1/connections/999", nil)
	if r, e = uc.Do(req); e != nil || r.StatusCode != 404 {
		t.Fatal("unknown id", e)
	}
	r.Body.Close()
	// TCP: no secret / wrong secret / right secret.
	for _, tc := range []struct {
		auth string
		want int
	}{{"", 401}, {"Bearer wrong-secret-0000000", 401}, {"Basic " + secret, 401}, {"Bearer " + secret, 200}} {
		req, _ := http.NewRequest("GET", "http://"+listen+"/v1/stats", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		r, e := http.DefaultClient.Do(req)
		if e != nil || r.StatusCode != tc.want {
			t.Fatalf("%q: %v %v", tc.auth, r, e)
		}
		r.Body.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Close(ctx)
	if _, e := os.Stat(sock); e == nil {
		t.Fatal("socket left behind")
	}
}

func TestStatsPersistence(t *testing.T) {
	echo := echoTCP(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "state", "x.stats.json")
	start := func() *Server {
		return startTest(t, inFor("socks5", nil), func(c *Config) { c.Stats = &StatsOptions{File: file} })
	}
	transfer := func(s *Server, n int) {
		c, code := socksConnect(t, s, echo)
		if code != 0 {
			t.Fatal(code)
		}
		writeAll(c, make([]byte, n))
		readN(c, n)
		c.Close()
		waitFor(t, func() bool { return s.tcpFlows.Load() == 0 })
	}
	stop := func(s *Server) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	}
	s := start()
	transfer(s, 1000)
	stop(s)
	if st, e := os.Stat(file); e != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("not saved on stop", e)
	}
	s = start()
	if got := s.reg.Total.Load(); got.Up != 1000 || got.Down != 1000 {
		t.Fatalf("not restored %+v", got)
	}
	transfer(s, 500)
	if got := s.reg.Total.Load(); got.Up != 1500 {
		t.Fatalf("not accumulated %+v", got)
	}
	if e := (apiBackend{s.core}).ResetStats(); e != nil {
		t.Fatal(e)
	}
	if got := s.reg.Total.Load(); got.Up != 0 || s.reg.Snapshot().Rules[0].Hits != 0 {
		t.Fatal("reset", got)
	}
	transfer(s, 7)
	stop(s)
	s = start()
	if got := s.reg.Total.Load(); got.Up != 7 {
		t.Fatalf("after reset %+v", got)
	}
	stop(s)
	// Corrupt file: warn, quarantine, start from zero.
	os.WriteFile(file, []byte(`{"version":1,"total":{"up":`), 0o600)
	var buf bytes.Buffer
	s = startTest(t, inFor("socks5", nil), func(c *Config) {
		c.Stats = &StatsOptions{File: file}
		c.Log = &LogOptions{File: filepath.Join(dir, "log")}
	})
	if got := s.reg.Total.Load(); got.Up != 0 {
		t.Fatal(got)
	}
	_ = buf
	stop(s)
	logs, _ := os.ReadFile(filepath.Join(dir, "log"))
	if !strings.Contains(string(logs), "kat event=stats_load_failed reason=corrupt action=start_from_zero") {
		t.Fatalf("no warning: %s", logs)
	}
	m, _ := filepath.Glob(file + ".corrupt-*")
	if len(m) != 1 {
		t.Fatal("corrupt file not kept aside", m)
	}
	// An unwritable location only warns; forwarding keeps working.
	ro := filepath.Join(dir, "ro")
	os.Mkdir(ro, 0o500)
	s = startTest(t, inFor("socks5", nil), func(c *Config) { c.Stats = &StatsOptions{File: filepath.Join(ro, "sub", "x.json")} })
	transfer(s, 10)
	stop(s)
}

func TestAccessLogLineScanner(t *testing.T) {
	// Every access line is one line even with hostile target names.
	var buf bytes.Buffer
	lg := &logger{write: func(p []byte) error { buf.Write(p); return nil }}
	lg.access.Store(true)
	s := &Server{core: &core{log: lg}}
	s.log.level.Store(int32(levelInfo))
	f := &flow{s: s, id: 7, network: "tcp", start: time.Now(), target: "a b\nkat event=fake:80", src: netip.MustParseAddr("2001:db8::1")}
	s.accessLine(f)
	sc := bufio.NewScanner(&buf)
	n := 0
	for sc.Scan() {
		n++
		if !strings.Contains(sc.Text(), "src=2001:db8::/48") {
			t.Fatal(sc.Text())
		}
	}
	if n != 1 {
		t.Fatal("line split", buf.String())
	}
	_ = io.Discard
}

// Groups and protocol outbounds: the guard applies to the final direct dial
// of client traffic only; Kat's own dial to an upstream on loopback is not
// client traffic. Chains and group counters follow the chosen members.
func TestGuardThroughGroupsAndUpstream(t *testing.T) {
	echo := echoTCP(t)
	uecho, _ := echoUDP(t)
	dns := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 60) })
	upCfg := Config{DNS: &DNSOptions{Server: "udp://" + dns.udp.LocalAddr().String()}, UDPBindIPv4: "127.0.0.1", Inbounds: []Inbound{{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: ssIn().SS}},
		Security: &SecurityOptions{AllowLoopback: true},
		Limits:   Limits{HandshakeTimeout: Duration(2 * time.Second), DialTimeout: Duration(2 * time.Second), DrainTimeout: Duration(time.Second), UDPIdle: Duration(2 * time.Second)}}
	up, e := Start(upCfg)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = up.Close(ctx)
	}()
	upPort := uint16(up.Addresses()[0].(*net.TCPAddr).Port)
	s := startTest(t, inFor("socks5", nil), func(c *Config) {
		c.Security = nil
		c.DNS = &DNSOptions{Server: "udp://" + dns.udp.LocalAddr().String()}
		c.Stats = &StatsOptions{Connections: true}
		c.Outbounds = []OutboundConfig{{Name: "up", Type: "shadowsocks", Server: "127.0.0.1", Port: upPort, Method: ssIn().SS.Method, Key: ssIn().SS.Key}}
		c.Groups = []GroupConfig{{Name: "sel", Type: "select", Members: []string{"direct", "up"}, Selected: "direct"}}
		c.Routing = &RoutingOptions{Rules: []RouteRule{{DomainSuffix: "viaup.test", Outbound: "sel2"}}, Final: "sel"}
		c.Groups = append(c.Groups, GroupConfig{Name: "sel2", Type: "select", Members: []string{"up"}})
	})
	// sel -> direct -> 127.0.0.1: refused.
	c, code := socksConnect(t, s, echo)
	c.Close()
	if code == 0 {
		t.Fatal("group direct member reached loopback")
	}
	// sel2 -> up (Kat dials 127.0.0.1 itself) -> upstream allows loopback.
	c, code = socksConnect(t, s, Address{"echo.viaup.test", echo.Port})
	if code != 0 {
		t.Fatal("upstream on loopback refused", code)
	}
	writeAll(c, []byte("abc"))
	if b, e := readN(c, 3); e != nil || string(b) != "abc" {
		t.Fatal(e)
	}
	list := s.connections()
	if len(list) != 1 || strings.Join(list[0].Chain, ">") != "sel2>up" || list[0].Rule != "domain_suffix:viaup.test->sel2" {
		t.Fatalf("%+v", list)
	}
	c.Close()
	waitFor(t, func() bool { return len(s.connections()) == 0 })
	// UDP through the group's direct member to loopback: refused.
	ctl, u, relay := socksAssociate(t, s, 0)
	defer ctl.Close()
	socksUDPSend(t, u, relay, uecho, []byte("x"), 0)
	u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, e := u.ReadFromUDP(make([]byte, 100)); e == nil {
		t.Fatal("UDP via group reached loopback")
	}
	snap := s.reg.Snapshot()
	var sel2, upc uint64
	for _, g := range snap.Groups {
		if g.Name == "sel2" {
			sel2 = g.Up
		}
	}
	for _, o := range snap.Outbounds {
		if o.Name == "up" {
			upc = o.Down
		}
	}
	if sel2 != 3 || upc != 3 {
		t.Fatalf("group/outbound counters %+v", snap)
	}
}
