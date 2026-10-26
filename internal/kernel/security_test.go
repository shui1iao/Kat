package kernel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---- SOCKS5 UDP reassembly ----

func newTestReassembly(maxBytes int, total int64, timeout time.Duration) (*reassembly, *fragmentPool) {
	p := &fragmentPool{}
	return newReassembly(p, func() int64 { return total }, maxBytes, timeout), p
}

func TestReassemblyOrdersDuplicatesAndLimits(t *testing.T) {
	a, b := Address{"127.0.0.1", 9}, Address{"127.0.0.1", 10}
	r, p := newTestReassembly(1024, 1<<20, time.Minute)
	// In order.
	r.add(1, a, []byte("ab"))
	r.add(2, a, []byte("cd"))
	if to, got, ok := r.add(3|0x80, a, []byte("ef")); !ok || string(got) != "abcdef" || to != a {
		t.Fatalf("in order: %q %v", got, ok)
	}
	// Out of order, with a duplicate.
	r.add(3|0x80, a, []byte("3"))
	r.add(1, a, []byte("1"))
	if _, _, ok := r.add(1, a, []byte("1")); ok {
		t.Fatal("duplicate completed")
	}
	if _, got, ok := r.add(2, a, []byte("2")); !ok || string(got) != "123" {
		t.Fatalf("reordered: %q %v", got, ok)
	}
	if p.dropped.Load() != 1 || p.reassembled.Load() != 2 || p.used.Load() != 0 {
		t.Fatalf("counters dropped=%d reassembled=%d used=%d", p.dropped.Load(), p.reassembled.Load(), p.used.Load())
	}
	// A changed duplicate or another destination starts a new datagram.
	r.add(1, a, []byte("old"))
	r.add(1, a, []byte("new"))
	r.add(1, b, []byte("x"))
	if _, got, ok := r.add(2|0x80, b, []byte("y")); !ok || string(got) != "xy" {
		t.Fatalf("restart: %q %v", got, ok)
	}
	// Malformed: position 0, last before a higher position, beyond the end.
	if _, _, ok := r.add(0x80, a, []byte("z")); ok {
		t.Fatal("position 0 accepted")
	}
	r.add(3, a, []byte("3"))
	r.add(2|0x80, a, []byte("2")) // inconsistent with position 3: restarts
	r.add(1, a, []byte("1"))
	if p.used.Load() != 0 || r.active {
		t.Fatalf("after completion used=%d active=%v", p.used.Load(), r.active)
	}
	// Per-association limit.
	r.add(1, a, make([]byte, 1000))
	if _, _, ok := r.add(2|0x80, a, make([]byte, 100)); ok || r.active || p.used.Load() != 0 {
		t.Fatal("association limit not applied")
	}
	r.close()
	if _, _, ok := r.add(1|0x80, a, []byte("x")); ok || p.used.Load() != 0 {
		t.Fatal("closed reassembly accepted a fragment")
	}
}

func TestReassemblyGlobalBudgetAndTimeout(t *testing.T) {
	a := Address{"127.0.0.1", 9}
	p := &fragmentPool{}
	limit := func() int64 { return 1500 }
	r1 := newReassembly(p, limit, 65535, 50*time.Millisecond)
	r2 := newReassembly(p, limit, 65535, 50*time.Millisecond)
	r1.add(1, a, make([]byte, 1000))
	r2.add(1, a, make([]byte, 400))
	if _, _, ok := r2.add(2|0x80, a, make([]byte, 200)); ok || r2.active {
		t.Fatal("global budget not applied")
	}
	if p.used.Load() != 1000 {
		t.Fatalf("used %d", p.used.Load())
	}
	time.Sleep(150 * time.Millisecond)
	if p.used.Load() != 0 {
		t.Fatalf("timeout did not release: %d", p.used.Load())
	}
	if _, _, ok := r1.add(2|0x80, a, []byte("late")); ok {
		t.Fatal("expired datagram completed")
	}
	r1.close()
	r2.close()
	if p.used.Load() != 0 {
		t.Fatal("bytes kept after close")
	}
}

func FuzzReassembly(f *testing.F) {
	f.Add([]byte{1, 0, 10, 0x82, 0, 10})
	f.Add([]byte{0x81, 1, 255, 0, 0, 0, 3, 0, 1})
	f.Fuzz(func(t *testing.T, ops []byte) {
		p := &fragmentPool{}
		const total = 8192
		r := newReassembly(p, func() int64 { return total }, 4096, time.Minute)
		targets := []Address{{"127.0.0.1", 1}, {"127.0.0.1", 2}}
		for len(ops) >= 3 {
			frag, tgt, size := ops[0], targets[ops[1]&1], int(ops[2])*int(ops[1]>>1+1)
			ops = ops[3:]
			payload := bytes.Repeat([]byte{frag}, size)
			_, out, ok := r.add(frag, tgt, payload)
			if ok && (len(out) > 4096 || len(out) > maxDatagram) {
				t.Fatalf("datagram of %d bytes", len(out))
			}
			if u := p.used.Load(); u < 0 || u > total || u > 4096 {
				t.Fatalf("used %d", u)
			}
		}
		r.close()
		if p.used.Load() != 0 {
			t.Fatalf("used %d after close", p.used.Load())
		}
	})
}

func TestSOCKSFragmentsEndToEnd(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), nil)
	target, _ := echoUDP(t)
	_, u, relay := socksAssociate(t, s, 0)
	socksUDPSend(t, u, relay, target, []byte("-world"), 2|0x80)
	socksUDPSend(t, u, relay, target, []byte("hello"), 1)
	if got := string(socksUDPRead(t, u)); got != "hello-world" {
		t.Fatalf("reassembled %q", got)
	}
	socksUDPSend(t, u, relay, target, []byte("plain"), 0)
	if got := string(socksUDPRead(t, u)); got != "plain" {
		t.Fatalf("unfragmented %q", got)
	}
	if s.frags.reassembled.Load() != 1 || s.frags.used.Load() != 0 {
		t.Fatal("reassembly not counted")
	}
}

// ---- source guard ----

func dialFrom(t *testing.T, src string, addr net.Addr) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, e := d.Dial("tcp", addr.String())
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

// socksTry runs a SOCKS5 username/password handshake from src and reports
// whether authentication succeeded (false also when the server closed the
// connection without answering).
func socksTry(t *testing.T, s *Server, src, pass string) bool {
	t.Helper()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, e := d.Dial("tcp", s.Addresses()[0].String())
	if errors.Is(e, syscall.ECONNRESET) {
		return false // accept-stage RST may race with connect completion
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if writeAll(c, []byte{5, 1, 2}) != nil {
		return false
	}
	if b, e := readN(c, 2); e != nil || b[1] != 2 {
		return false
	}
	b := append([]byte{1, 4}, "user"...)
	b = append(b, byte(len(pass)))
	b = append(b, pass...)
	if writeAll(c, b) != nil {
		return false
	}
	r, e := readN(c, 2)
	return e == nil && r[1] == 0
}

// refusedAtAccept reports whether a connection from src is closed by the
// server before any byte is exchanged.
func refusedAtAccept(t *testing.T, s *Server, src string) bool {
	t.Helper()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, e := d.Dial("tcp", s.Addresses()[0].String())
	if errors.Is(e, syscall.ECONNRESET) {
		return true
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, e = c.Read(make([]byte, 1))
	return e != nil && !isTimeout(e)
}

func TestAuthBanSOCKS(t *testing.T) {
	in := inFor("socks5", nil)
	in.Users = []User{{Username: "user", Password: "pass"}}
	s := startTest(t, in, func(c *Config) {
		c.Security.AuthBan = &AuthBanOptions{Enabled: true, Threshold: 3, Window: Duration(10 * time.Second), Duration: Duration(time.Second)}
	})
	for i := 0; i < 3; i++ {
		if socksTry(t, s, "127.0.0.2", "wrong") {
			t.Fatal("wrong password accepted")
		}
	}
	waitFor(t, func() bool { return len(s.guard.list()) == 1 })
	if !refusedAtAccept(t, s, "127.0.0.2") || socksTry(t, s, "127.0.0.2", "pass") {
		t.Fatal("banned source accepted")
	}
	if !socksTry(t, s, "127.0.0.3", "pass") {
		t.Fatal("other source refused")
	}
	if l := s.guard.list(); l[0].Source != "127.0.0.2" || l[0].Failures != 3 || l[0].Protocol != "socks5" {
		t.Fatalf("ban entry %+v", l[0])
	}
	if v := s.StatsView().Security; v.Banned != 1 || v.AuthFailures != 3 || v.RefusedBanned < 2 {
		t.Fatalf("security view %+v", v)
	}
	// Lifted by the API, banned again, then expired.
	if found, e := s.guard.remove("127.0.0.2"); !found || e != nil {
		t.Fatal("remove", found, e)
	}
	if !socksTry(t, s, "127.0.0.2", "pass") {
		t.Fatal("unbanned source refused")
	}
	for i := 0; i < 3; i++ {
		socksTry(t, s, "127.0.0.2", "wrong")
	}
	waitFor(t, func() bool { return refusedAtAccept(t, s, "127.0.0.2") })
	time.Sleep(1200 * time.Millisecond)
	waitFor(t, func() bool { return len(s.guard.list()) == 0 && s.guard.nbans.Load() == 0 })
	if !socksTry(t, s, "127.0.0.2", "pass") {
		t.Fatal("ban did not expire")
	}
	if _, e := s.guard.remove("not-an-ip"); e == nil {
		t.Fatal("invalid source accepted")
	}
}

func TestAuthBanSurvivesReloadAndDisableClears(t *testing.T) {
	in := inFor("socks5", nil)
	in.Users = []User{{Username: "user", Password: "pass"}}
	in.Listen = reloadPort(t)
	mk := func(enabled bool) Config {
		c := Config{Inbounds: []Inbound{in}, Security: &SecurityOptions{AllowLoopback: true, AuthBan: &AuthBanOptions{Enabled: enabled, Threshold: 2, Duration: Duration(time.Minute)}}}
		if e := c.Validate(); e != nil {
			t.Fatal(e)
		}
		return c
	}
	next := mk(true)
	s := startReloadable(t, mk(true), &next)
	socksTry(t, s, "127.0.0.5", "wrong")
	socksTry(t, s, "127.0.0.5", "wrong")
	waitFor(t, func() bool { return len(s.guard.list()) == 1 })
	next.Security.AuthBan.Threshold = 5
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if len(s.guard.list()) != 1 || !refusedAtAccept(t, s, "127.0.0.5") {
		t.Fatal("ban lost by reload")
	}
	next = mk(false)
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if len(s.guard.list()) != 0 || !socksTry(t, s, "127.0.0.5", "pass") {
		t.Fatal("disabled banning kept the table")
	}
	// Disabled: failures are counted but never ban.
	for i := 0; i < 5; i++ {
		socksTry(t, s, "127.0.0.5", "wrong")
	}
	if len(s.guard.list()) != 0 {
		t.Fatal("ban while disabled")
	}
}

func TestSourceListsAndPerIPLimitReload(t *testing.T) {
	echo := echoTCP(t)
	in := inFor("socks5", nil)
	in.Listen = reloadPort(t)
	mk := func(limit int, allow, deny []string) Config {
		i := in
		i.Sources = &SourceOptions{Allow: allow, Deny: deny}
		c := Config{Inbounds: []Inbound{i}, Security: &SecurityOptions{AllowLoopback: true, MaxConnectionsPerIP: limit}}
		if e := c.Validate(); e != nil {
			t.Fatal(e)
		}
		return c
	}
	next := mk(2, nil, []string{"127.0.0.9"})
	s := startReloadable(t, next, &next)
	connect := func(src string) net.Conn {
		c := dialFrom(t, src, s.Addresses()[0])
		socksGreeting(t, c, false, "")
		writeAll(c, peerHeader("socks5", 1, echo))
		peerResponse(t, c, "socks5")
		if !echoOnce(c, "x") {
			t.Fatal("echo")
		}
		return c
	}
	if !refusedAtAccept(t, s, "127.0.0.9") {
		t.Fatal("denied source accepted")
	}
	a, b := connect("127.0.0.10"), connect("127.0.0.10")
	if !refusedAtAccept(t, s, "127.0.0.10") {
		t.Fatal("per-IP limit not applied")
	}
	connect("127.0.0.11")
	// Reload: limit 1 and an allow list without 127.0.0.11. Existing
	// connections continue; new ones follow the new rules.
	next = mk(1, []string{"127.0.0.10/32", "127.0.0.12"}, []string{"127.0.0.9"})
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if !echoOnce(a, "a") || !echoOnce(b, "b") {
		t.Fatal("existing connections affected")
	}
	if !refusedAtAccept(t, s, "127.0.0.11") || !refusedAtAccept(t, s, "127.0.0.10") {
		t.Fatal("new rules not applied")
	}
	connect("127.0.0.12")
	a.Close()
	b.Close()
	waitFor(t, func() bool {
		s.guard.mu.Lock()
		defer s.guard.mu.Unlock()
		return s.guard.conns[guardKey(mustAddr("127.0.0.10"))] == 0
	})
	connect("127.0.0.10")
	v := s.StatsView().Security
	if v.RefusedSources < 2 || v.RefusedPerIP < 2 {
		t.Fatalf("security view %+v", v)
	}
}

func TestSourceListValidation(t *testing.T) {
	for _, bad := range [][]string{{"10.0.0.0/33"}, {"host"}, {"fe80::1%eth0"}, {"::ffff:1.2.3.4/90"}} {
		in := inFor("socks5", nil)
		in.Listen = "127.0.0.1:0"
		in.Sources = &SourceOptions{Allow: bad}
		c := Config{Inbounds: []Inbound{in}}
		if c.Validate() == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	in := inFor("socks5", nil)
	in.Listen = "127.0.0.1:0"
	in.Sources = &SourceOptions{Allow: []string{"::ffff:10.1.0.0/112", "2001:db8::/32"}}
	c := Config{Inbounds: []Inbound{in}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	got := c.Inbounds[0]
	if !got.sourceAllowed(mustAddr("10.1.2.3")) || got.sourceAllowed(mustAddr("10.2.0.1")) || !got.sourceAllowed(mustAddr("2001:db8::5")) {
		t.Fatal("source matching")
	}
	if k, ok := parseBanKey("2001:db8:1:2:3::9"); !ok || guardKeyString(k) != "2001:db8:1:2::/64" {
		t.Fatal("IPv6 ban key", k)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// ---- Trojan fallback ----

func trojanSend(t *testing.T, s *Server, pool *x509.CertPool, data []byte) net.Conn {
	t.Helper()
	cfg := &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12, RootCAs: pool}
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	if len(data) > 0 {
		writeAll(c, data)
	}
	return c
}

func TestTrojanFallback(t *testing.T) {
	cert, pool := testCert(t)
	body := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		io.WriteString(w, body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	in := inFor("trojan", cert)
	in.Fallback = ln.Addr().String()
	// Default security options: loopback destinations refused, yet the
	// fallback (dialed by Kat itself) is loopback.
	s := startTest(t, in, func(c *Config) {
		c.Security = &SecurityOptions{AuthBan: &AuthBanOptions{Enabled: true, Threshold: 100}}
	})
	for _, req := range []string{"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", strings.Repeat("a", 56) + "\r\n"} {
		c := trojanSend(t, s, pool, []byte(req))
		if strings.HasPrefix(req, "GET") {
			got, e := io.ReadAll(c)
			if e != nil || !bytes.HasSuffix(got, []byte(body)) || !bytes.HasPrefix(got, []byte("HTTP/1.1 200")) {
				t.Fatalf("fallback response: %d bytes %v", len(got), e)
			}
		} else {
			// Hash-shaped wrong password: counted, then relayed (the web
			// server answers 400 to it).
			writeAll(c, []byte("GET / HTTP/1.1\r\n\r\n"))
			got, _ := io.ReadAll(c)
			if !bytes.HasPrefix(got, []byte("HTTP/1.1 400")) {
				t.Fatalf("relayed wrong password: %q", got[:min(len(got), 40)])
			}
		}
	}
	if s.fallbacks.Load() != 2 || s.guard.authFailures.Load() != 1 {
		t.Fatalf("fallbacks=%d failures=%d", s.fallbacks.Load(), s.guard.authFailures.Load())
	}
	// The real protocol still works.
	echo := echoTCP(t)
	s2 := startTest(t, in, nil)
	c := trojanSend(t, s2, pool, peerHeader("trojan", 1, echo))
	if !echoOnce(c, "hello") {
		t.Fatal("Trojan request failed with fallback configured")
	}
	// Unreachable fallback: closed cleanly (close_notify, EOF).
	srv.Close()
	c = trojanSend(t, s, pool, []byte("GET / HTTP/1.1\r\n\r\n"))
	if n, e := c.Read(make([]byte, 1)); n != 0 || !errors.Is(e, io.EOF) {
		t.Fatalf("unreachable fallback: %d %v", n, e)
	}
}

func TestTrojanWithoutFallbackFailsFast(t *testing.T) {
	cert, pool := testCert(t)
	s := startTest(t, inFor("trojan", cert), nil)
	c := trojanSend(t, s, pool, []byte("GET / HTTP/1.1\r\n\r\n"))
	start := time.Now()
	if n, _ := c.Read(make([]byte, 1)); n != 0 || time.Since(start) > 500*time.Millisecond {
		t.Fatal("non-Trojan request not closed at once")
	}
}

// ---- SOCKS5 BIND ----

func socksBindRequest(t *testing.T, s *Server, expect Address) (net.Conn, byte, Address) {
	t.Helper()
	c := dialPeer(t, s, nil)
	socksGreeting(t, c, false, "")
	writeAll(c, peerHeader("socks5", 2, expect))
	h, e := readN(c, 3)
	if e != nil {
		t.Fatal(e)
	}
	a, e := readAddress(c, false)
	if e != nil {
		t.Fatal(e)
	}
	return c, h[1], a
}

func bindInbound(t *testing.T, timeout time.Duration) Inbound {
	in := inFor("socks5", nil)
	lo := 0
	for lo == 0 || lo > 65000 {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		lo = l.Addr().(*net.TCPAddr).Port
		l.Close()
	}
	in.SOCKS5 = &SOCKS5Options{Bind: &SOCKSBindOptions{Listen: "127.0.0.1", Ports: strconv.Itoa(lo) + "-" + strconv.Itoa(lo+3), Timeout: Duration(timeout)}}
	return in
}

func TestSOCKSBind(t *testing.T) {
	s := startTest(t, bindInbound(t, time.Second), nil)
	// Full flow: two replies, then relay both ways.
	c, rep, bound := socksBindRequest(t, s, Address{"127.0.0.1", 0})
	if rep != 0 || bound.Host != "127.0.0.1" || bound.Port == 0 {
		t.Fatalf("first reply %d %v", rep, bound)
	}
	peer, e := net.Dial("tcp", bound.String())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	h, _ := readN(c, 3)
	from, _ := readAddress(c, false)
	if h[1] != 0 || from.String() != peer.LocalAddr().String() {
		t.Fatalf("second reply %x %v want %v", h, from, peer.LocalAddr())
	}
	writeAll(peer, []byte("from-peer"))
	if b, _ := readN(c, 9); string(b) != "from-peer" {
		t.Fatal("peer->client")
	}
	writeAll(c, []byte("to-peer"))
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	if b, _ := readN(peer, 7); string(b) != "to-peer" {
		t.Fatal("client->peer")
	}
	// The listening port was closed after the first connection.
	if x, e := net.DialTimeout("tcp", bound.String(), 200*time.Millisecond); e == nil {
		x.Close()
		t.Fatal("BIND port still listening")
	}
	c.Close()
	peer.Close()
	// Wrong peer is ignored, then the wait times out: reply 1.
	c, rep, bound = socksBindRequest(t, s, Address{"127.0.0.2", 0})
	if rep != 0 {
		t.Fatal("bind reply", rep)
	}
	wrong, e := net.Dial("tcp", bound.String())
	if e == nil {
		wrong.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := wrong.Read(make([]byte, 1)); e == nil {
			t.Fatal("wrong peer relayed")
		}
		wrong.Close()
	}
	h, e = readN(c, 3)
	if e != nil || h[1] != 1 {
		t.Fatalf("timeout reply %x %v", h, e)
	}
	waitFor(t, func() bool { return s.bindActive.Load() == 0 && s.Stats().Dials == 0 })
}

func TestSOCKSBindRefused(t *testing.T) {
	// Default security options refuse loopback peers.
	in := bindInbound(t, time.Second)
	s := startTest(t, in, func(c *Config) { c.Security = nil })
	_, rep, _ := socksBindRequest(t, s, Address{"127.0.0.1", 0})
	if rep != 2 {
		t.Fatalf("loopback BIND reply %d, want 2", rep)
	}
	// BIND not configured: command not supported.
	s2 := startTest(t, inFor("socks5", nil), nil)
	_, rep, _ = socksBindRequest(t, s2, Address{"0.0.0.0", 0})
	if rep != 7 {
		t.Fatalf("reply %d, want 7", rep)
	}
	// BIND ports may not include a listener of Kat.
	bad := bindInbound(t, time.Second)
	bad.Listen = "127.0.0.1:" + strings.Split(bad.SOCKS5.Bind.Ports, "-")[0]
	c := Config{Inbounds: []Inbound{bad}}
	if c.Validate() == nil {
		t.Fatal("BIND range over the inbound port accepted")
	}
}

// An accepted old-generation handshake must not recreate a ban after a
// reload disabled the feature and emptied the process-wide table.
func TestAuthBanDisabledBeforeOldHandshakeFinishes(t *testing.T) {
	in := inFor("socks5", nil)
	in.Listen = reloadPort(t)
	in.Users = []User{{Username: "user", Password: "pass"}}
	mk := func(enabled bool) Config {
		return Config{Inbounds: []Inbound{in}, Security: &SecurityOptions{
			AllowLoopback: true, AuthBan: &AuthBanOptions{Enabled: enabled, Threshold: 1},
		}}
	}
	next := mk(true)
	s := startReloadable(t, next, &next)
	c := dialFrom(t, "127.0.0.81", s.Addresses()[0])
	if e := writeAll(c, []byte{5, 1, 2}); e != nil {
		t.Fatal(e)
	}
	if b, e := readN(c, 2); e != nil || !bytes.Equal(b, []byte{5, 2}) {
		t.Fatalf("greeting %x %v", b, e)
	}
	next = mk(false)
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if e := writeAll(c, []byte{1, 4, 117, 115, 101, 114, 5, 119, 114, 111, 110, 103}); e != nil {
		t.Fatal(e)
	}
	_, _ = readN(c, 2)
	waitFor(t, func() bool { return s.StatsView().Security.AuthFailures == 1 })
	if v := s.StatsView().Security; v.AuthBanEnabled || v.Banned != 0 || v.TrackedSources != 0 {
		t.Fatalf("old handshake repopulated disabled guard: %+v", v)
	}
}

func TestReassemblyEmptyDuplicatesDoNotFillMissingPositions(t *testing.T) {
	r, p := newTestReassembly(1024, 65535, time.Minute)
	defer r.close()
	a := Address{"127.0.0.1", 9}
	r.add(1, a, nil)
	r.add(1, a, nil)
	if _, _, ok := r.add(0x83, a, []byte("C")); ok {
		t.Fatal("duplicate empty fragment filled missing position 2")
	}
	if _, b, ok := r.add(2, a, []byte("B")); !ok || string(b) != "BC" {
		t.Fatalf("completion %q %v", b, ok)
	}
	if p.used.Load() != 0 || p.reassembled.Load() != 1 || p.dropped.Load() != 1 {
		t.Fatal("incorrect counters after empty duplicate")
	}
}
