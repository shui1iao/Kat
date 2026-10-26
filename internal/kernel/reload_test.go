package kernel

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reloadPort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func reloadLimits() Limits {
	return Limits{Connections: 32, Handshakes: 16, Dials: 8, UDPAssociations: 8, UDPQueue: 4, UDPTargets: 4, PoolBuffers: 4, HandshakeTimeout: Duration(time.Second), DialTimeout: Duration(time.Second), DrainTimeout: Duration(2 * time.Second), UDPIdle: Duration(time.Second)}
}

func socksCfg(listens ...string) Config {
	c := Config{UDPBindIPv4: "127.0.0.1", UDPBindIPv6: "::1", Limits: reloadLimits(), Security: &SecurityOptions{AllowLoopback: true}}
	for _, l := range listens {
		c.Inbounds = append(c.Inbounds, Inbound{Protocol: "socks5", Listen: l})
	}
	return c
}

// socksTo opens a no-auth SOCKS5 CONNECT on listen to a; ok=false when the
// inbound refused the connection or the no-auth method.
func socksTo(t *testing.T, listen string, a Address) (net.Conn, bool) {
	t.Helper()
	c, e := net.DialTimeout("tcp", listen, time.Second)
	if e != nil {
		return nil, false
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if writeAll(c, []byte{5, 1, 0}) != nil {
		c.Close()
		return nil, false
	}
	b, e := readN(c, 2)
	if e != nil || b[1] != 0 {
		c.Close()
		return nil, false
	}
	if writeAll(c, peerHeader("socks5", 1, a)) != nil {
		c.Close()
		return nil, false
	}
	h, e := readN(c, 3)
	if e != nil || h[1] != 0 {
		c.Close()
		return nil, false
	}
	if _, e := readAddress(c, false); e != nil {
		c.Close()
		return nil, false
	}
	return c, true
}

func echoOnce(c net.Conn, msg string) bool {
	if writeAll(c, []byte(msg)) != nil {
		return false
	}
	b, e := readN(c, len(msg))
	return e == nil && string(b) == msg
}

func startReloadable(t *testing.T, c Config, next *Config) *Server {
	t.Helper()
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	s.SetConfigLoader(func() (Config, error) { return *next, nil })
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

func TestReloadInboundsKeepSocketsAndConnections(t *testing.T) {
	echo := echoTCP(t)
	p1, p2 := reloadPort(t), reloadPort(t)
	next := socksCfg(p1)
	s := startReloadable(t, socksCfg(p1), &next)
	ln1 := s.core.tcpEntries[listenKey(p1)].ln
	old, ok := socksTo(t, p1, echo)
	if !ok || !echoOnce(old, "before") {
		t.Fatal("initial connection")
	}
	defer old.Close()

	// p1 now requires authentication, p2 is added.
	next = socksCfg(p1, p2)
	next.Inbounds[0].Users = []User{{Username: "user", Password: "secret"}}
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if s.core.tcpEntries[listenKey(p1)].ln != ln1 {
		t.Fatal("unchanged address was bound again")
	}
	if !echoOnce(old, "after-first") {
		t.Fatal("existing connection interrupted")
	}
	if c, ok := socksTo(t, p1, echo); ok {
		c.Close()
		t.Fatal("new connection used the old (no-auth) configuration")
	}
	if c, ok := socksTo(t, p2, echo); !ok || !echoOnce(c, "p2") {
		t.Fatal("added inbound not serving")
	} else {
		c.Close()
	}

	// p1 removed: no new connections, the old one continues.
	next = socksCfg(p2)
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if c, e := net.DialTimeout("tcp", p1, 300*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("removed inbound still accepts")
	}
	if !echoOnce(old, "after-remove") {
		t.Fatal("existing connection interrupted by removal")
	}
	if v := s.StatsView().Reload; v.LiveGenerations < 2 {
		t.Fatalf("generation of the open connection released early: %+v", v)
	}
	old.Close()
	waitFor(t, func() bool { return s.StatsView().Reload.LiveGenerations == 1 })
	if v := s.StatsView().Reload; v.Generation != 3 || v.Reloads != 2 {
		t.Fatalf("reload view %+v", v)
	}
}

func TestReloadFailureKeepsRunningConfiguration(t *testing.T) {
	echo := echoTCP(t)
	busy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	p1 := reloadPort(t)
	next := socksCfg(p1)
	s := startReloadable(t, socksCfg(p1), &next)
	// Allocate p2 only after p1 and busy are bound. Two consecutive closed
	// ephemeral listeners can receive the same port, invalidating this fixture.
	p2 := reloadPort(t)

	// New port p2 plus an occupied port: nothing may change, p2 must not stay bound.
	next = socksCfg(p1, p2, busy.Addr().String())
	_, e = s.Reload("test")
	var re *ReloadError
	if !errors.As(e, &re) || re.Stage != "bind_tcp" {
		t.Fatalf("want bind_tcp failure, got %v", e)
	}
	if len(s.core.tcpEntries) != 1 {
		t.Fatalf("listeners after failed reload: %d", len(s.core.tcpEntries))
	}
	if l, e := net.Listen("tcp4", p2); e != nil {
		t.Fatal("port of the refused configuration left bound")
	} else {
		l.Close()
	}
	// Invalid configuration.
	next = socksCfg(p1)
	next.Inbounds[0].Protocol = "nope"
	if _, e := s.Reload("test"); !errors.As(e, &re) || re.Stage != "validate" {
		t.Fatalf("want validate failure, got %v", e)
	}
	// Loader failure (syntax error).
	s.SetConfigLoader(func() (Config, error) { return Config{}, errors.New("invalid configuration JSON") })
	if _, e := s.Reload("test"); !errors.As(e, &re) || re.Stage != "load" {
		t.Fatalf("want load failure, got %v", e)
	}
	if c, ok := socksTo(t, p1, echo); !ok || !echoOnce(c, "still") {
		t.Fatal("running configuration damaged by failed reloads")
	} else {
		c.Close()
	}
	if v := s.StatsView().Reload; v.Failures != 3 || v.Generation != 1 || v.LiveGenerations != 1 {
		t.Fatalf("reload view %+v", v)
	}
	// refused reloads do not consume generation numbers
	next = socksCfg(p1)
	s.SetConfigLoader(func() (Config, error) { return next, nil })
	if r, e := s.Reload("test"); e != nil || r.Generation != 2 {
		t.Fatalf("valid reload after refused ones: %+v %v", r, e)
	}
}

func selectCfg(statsFile, def string, members ...string) Config {
	c := socksCfg("127.0.0.1:0")
	c.Groups = []GroupConfig{{Name: "h", Type: "select", Members: []string{"direct"}}, {Name: "g", Type: "select", Members: members, Selected: def}}
	c.Stats = &StatsOptions{File: statsFile}
	return c
}

func currentOf(t *testing.T, s *Server, name string) (string, string) {
	t.Helper()
	for _, g := range s.SelectGroups() {
		if g.Name == name {
			return g.Current, g.Source
		}
	}
	t.Fatalf("group %s missing", name)
	return "", ""
}

func TestSelectPersistenceMatrix(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "x.stats.json")
	restart := func(s *Server, c Config, next *Config) *Server {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
		return startReloadable(t, c, next)
	}
	base := selectCfg(file, "", "direct", "reject", "h")
	next := base
	s := startReloadable(t, base, &next)
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal(cur, src)
	}
	// Running switch, unknown member refused.
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	var se *SelectError
	if e := s.Select("g", "nope"); !errors.As(e, &se) || se.Code != "unknown_member" {
		t.Fatal(e)
	}
	if e := s.Select("zz", "h"); !errors.As(e, &se) || se.Code != "unknown_group" {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "x.select.json")); e != nil || !strings.Contains(string(b), `"selected": "h"`) {
		t.Fatalf("state file %s %v", b, e)
	}
	// Kept by reload and by restart.
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if cur, src := currentOf(t, s, "g"); cur != "h" || src != "runtime" {
		t.Fatal("reload", cur, src)
	}
	s = restart(s, base, &next)
	if cur, _ := currentOf(t, s, "g"); cur != "h" {
		t.Fatal("restart", cur)
	}
	// Configured default changed (reload): the configuration wins.
	next = selectCfg(file, "reject", "direct", "reject", "h")
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if cur, src := currentOf(t, s, "g"); cur != "reject" || src != "config" {
		t.Fatal("default changed by reload", cur, src)
	}
	// Configured default changed between runs (restart).
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	changed := selectCfg(file, "direct", "direct", "reject", "h")
	next = changed
	s = restart(s, changed, &next)
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal("default changed by restart", cur, src)
	}
	// Member removed.
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	next = selectCfg(file, "direct", "direct", "reject")
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal("member removed", cur, src)
	}
	// Corrupt state file: warning, configured value.
	if e := s.Select("g", "reject"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = s.Close(ctx)
	cancel()
	if e := os.WriteFile(filepath.Join(dir, "x.select.json"), []byte("{broken"), 0o600); e != nil {
		t.Fatal(e)
	}
	s = startReloadable(t, next, &next)
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal("corrupt state", cur, src)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "x.select.json.corrupt-*")); len(m) != 1 {
		t.Fatal("corrupt state file not kept aside", m)
	}
}

func TestReloadStatisticsContinue(t *testing.T) {
	echo := echoTCP(t)
	p1, p2 := reloadPort(t), reloadPort(t)
	next := socksCfg(p1)
	s := startReloadable(t, socksCfg(p1), &next)
	c, ok := socksTo(t, p1, echo)
	if !ok || !echoOnce(c, "0123456789") {
		t.Fatal("connect")
	}
	next = socksCfg(p1, p2)
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if !echoOnce(c, "abcdefghij") {
		t.Fatal("echo after reload")
	}
	c.Close()
	waitFor(t, func() bool { return s.StatsView().Connections.TCP == 0 })
	v := s.StatsView().Cumulative
	if v.Total.Up != 20 || v.Total.Down != 20 {
		t.Fatalf("total %+v", v.Total)
	}
	var in1 *uint64
	for _, n := range v.Inbounds {
		if n.Name == "socks5/"+p1 {
			up := n.Up
			in1 = &up
		}
	}
	if in1 == nil || *in1 != 20 || len(v.Inbounds) != 2 {
		t.Fatalf("inbounds %+v", v.Inbounds)
	}
}

// An AnyTLS session (pooled by clients, effectively unbounded lifetime) must
// not pin the generation that accepted it: only its open streams do.
func TestReloadAnyTLSSessionDoesNotPinGeneration(t *testing.T) {
	cert, pool := testCert(t)
	target := echoTCP(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	c := atBegin(t, s, pool, 2, in.Listen)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	p := []byte("stream-one")
	atOpen(t, c, 1, target, p)
	if got := atPayload(t, c, 1, len(p)); string(got) != string(p) {
		t.Fatal("stream 1")
	}
	// stream 1 stays open across the reload: it holds generation 1.
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	v := s.StatsView().Reload
	if v.LiveGenerations != 2 || len(v.Retained) != 1 || v.Retained[0].Generation != 1 || v.Retained[0].References != 1 {
		t.Fatalf("open stream must retain generation 1: %+v", v)
	}
	writeAll(c, atFrame(3, 1, nil))
	waitFor(t, func() bool { return s.StatsView().Reload.LiveGenerations == 1 })
	// The idle session survives further reloads without retaining anything
	// and keeps serving new streams (routed by the current generation).
	for i := 0; i < 3; i++ {
		if _, e := s.Reload("test"); e != nil {
			t.Fatal(e)
		}
	}
	if v := s.StatsView().Reload; v.LiveGenerations != 1 || len(v.Retained) != 0 || v.Generation != 5 {
		t.Fatalf("idle session retained a generation: %+v", v)
	}
	p = []byte("stream-two")
	atOpen(t, c, 2, target, p)
	if got := atPayload(t, c, 2, len(p)); string(got) != string(p) {
		t.Fatal("stream 2 on the old session")
	}
	writeAll(c, atFrame(3, 2, nil))
	c.Close()
	waitFor(t, func() bool { v := s.StatsView().Reload; return v.LiveGenerations == 1 && s.Stats().Active == 0 })
}

// A finished SS UDP association drops its generation reference and its
// socket's association count: superseded generations are released and the
// UDP socket of a removed inbound closes with its last association.
func TestReloadSSUDPAssociationReleasesGeneration(t *testing.T) {
	listen := reloadPort(t)
	in := Inbound{Protocol: "shadowsocks", Listen: listen, SS: &SSOptions{Method: "aes-128-gcm", Password: "source-fixture", Salts2017: 16}}
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	client, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	target := localUDP(t)
	endpoint, _ := net.ResolveUDPAddr("udp4", listen)
	send := func() {
		t.Helper()
		salt := make([]byte, 16)
		rand.Read(salt)
		a := idle17AEAD(t, salt)
		wire := append(salt, a.Seal(nil, make([]byte, 12), append(peerAddr(addrFromNet(target.LocalAddr()), false), []byte("request")...), nil)...)
		if _, e := client.WriteToUDP(wire, endpoint); e != nil {
			t.Fatal(e)
		}
		if p, _ := recvUDP(t, target); string(p) != "request" {
			t.Fatal("payload", string(p))
		}
	}
	send()
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if v := s.StatsView().Reload; v.LiveGenerations != 2 {
		t.Fatalf("open association must retain generation 1: %+v", v)
	}
	// UDPIdle is 1s in reloadLimits.
	waitFor(t, func() bool { return s.StatsView().Reload.LiveGenerations == 1 && s.Stats().UDP == 0 })

	// Remove the inbound while an association created on its socket is open.
	send()
	waitFor(t, func() bool { return s.Stats().UDP == 1 })
	next = socksCfg(reloadPort(t))
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	s.core.udpMu.Lock()
	n := len(s.core.udpEntries)
	s.core.udpMu.Unlock()
	if n != 1 {
		t.Fatal("removed inbound's UDP socket closed under its association")
	}
	waitFor(t, func() bool {
		s.core.udpMu.Lock()
		defer s.core.udpMu.Unlock()
		return len(s.core.udpEntries) == 0 && s.StatsView().Reload.LiveGenerations == 1
	})
}
