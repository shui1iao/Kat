package group

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
)

// ---- fixtures: real protocol outbounds over the real direct dialer ----

var refusedSSKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 16))

// closedPort returns a loopback port with no listener (connect is refused).
func closedPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return uint16(p)
}

// socksReplyServer is a minimal SOCKS5 server that answers every CONNECT with
// the given reply code (5 = "connection refused" by the destination).
func socksReplyServer(t *testing.T, code byte) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 262)
				if _, err := io.ReadFull(c, b[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, b[:b[1]]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, b[:4]); err != nil {
					return
				}
				var n int
				switch b[3] {
				case 1:
					n = 4 + 2
				case 4:
					n = 16 + 2
				case 3:
					if _, err := io.ReadFull(c, b[:1]); err != nil {
						return
					}
					n = int(b[0]) + 2
				default:
					return
				}
				if _, err := io.ReadFull(c, b[:n]); err != nil {
					return
				}
				c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func mustOut(t *testing.T, o outbound.Outbound, err error) outbound.Outbound {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

func socksOut(t *testing.T, name string, port uint16, under outbound.Dialer) outbound.Outbound {
	o, err := socks5.New(outbound.Options{Name: name, Type: "socks5", Server: "127.0.0.1", Port: port}, under)
	return mustOut(t, o, err)
}

func trojanOut(t *testing.T, name string, port uint16, under outbound.Dialer) outbound.Outbound {
	o, err := trojan.New(outbound.Options{Name: name, Type: "trojan", Server: "127.0.0.1", Port: port, Password: "refused-test",
		TLS: &outbound.TLSOptions{Insecure: true}}, under)
	return mustOut(t, o, err)
}

func dialTo(g outbound.Dialer, dst outbound.Addr) (string, error) {
	c, err := g.DialTCP(context.Background(), dst)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return ownerOf(c), nil
}

// ---- immediate re-test: the member's own proxy server refused ----

func TestURLTestServerRefusedRetestsImmediately(t *testing.T) {
	under := direct.New(direct.Options{})
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, port uint16) outbound.Outbound
	}{
		{"socks5", func(t *testing.T, p uint16) outbound.Outbound { return socksOut(t, "a", p, under) }},
		{"shadowsocks", func(t *testing.T, p uint16) outbound.Outbound {
			o, err := ss.New(outbound.Options{Name: "a", Type: "shadowsocks", Server: "127.0.0.1", Port: p,
				Method: "2022-blake3-aes-128-gcm", Key: refusedSSKey}, under)
			return mustOut(t, o, err)
		}},
		{"trojan", func(t *testing.T, p uint16) outbound.Outbound { return trojanOut(t, "a", p, under) }},
		{"anytls", func(t *testing.T, p uint16) outbound.Outbound {
			o, err := anytls.New(outbound.Options{Name: "a", Type: "anytls", Server: "127.0.0.1", Port: p, Password: "refused-test",
				TLS: &outbound.TLSOptions{Insecure: true}}, under)
			return mustOut(t, o, err)
		}},
		// chain: the first hop's server refuses at the local socket
		{"chain-first-hop", func(t *testing.T, p uint16) outbound.Outbound {
			return trojanOut(t, "a", 443, socksOut(t, "hop", p, under))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.build(t, closedPort(t)), newFake("b")
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 100 * ms_})
			ev := &eventLog{}
			g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, ev)
			g.Start(context.Background())
			probeNow(t, g)
			if g.Current() != "a" {
				t.Fatalf("after first round current %q, want a", g.Current())
			}
			p.set("a", 0, true) // its server is down, so the re-test probe fails too
			// one connection: a's server refuses, the dial is retried on b
			// (nothing was sent yet) and the re-test starts at once
			got, err := dialTo(g, outbound.Addr{Host: "x.test", Port: 443})
			if err != nil || got != "b" {
				t.Fatalf("dial via %q err %v, want b", got, err)
			}
			waitRounds(t, g, 2)
			if g.Current() != "b" {
				t.Fatalf("after one refusal current %q, want b", g.Current())
			}
			if sw := switches(ev); len(sw) != 1 || sw[0] != "a>b" {
				t.Fatalf("switch events %v", sw)
			}
			if p.count("a") != 2 || p.count("b") != 2 {
				t.Fatalf("probes a=%d b=%d, want one re-test round", p.count("a"), p.count("b"))
			}
			if s := snapMember(g, "a"); s.Failures != 0 {
				t.Fatalf("failure window not reset by the re-test: %d", s.Failures)
			}
			if got := dial(t, g, "x.test"); got != "b" {
				t.Fatalf("next dial via %q", got)
			}
		})
	}
}

// A refusal while a re-test is already running does not start another one
// (same de-duplication as every other trigger).
func TestURLTestServerRefusedNoDuplicateRound(t *testing.T) {
	a, b := socksOut(t, "a", closedPort(t), direct.New(direct.Options{})), newFake("b")
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 100 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	probeNow(t, g)
	block := make(chan struct{})
	p.mu.Lock()
	p.block = block
	p.mu.Unlock()
	p.set("a", 0, true)
	for i := 0; i < 3; i++ { // first refusal starts the round; the others find it running
		if got, err := dialTo(g, outbound.Addr{Host: "x.test", Port: 443}); err != nil || got != "b" {
			t.Fatalf("dial %d via %q err %v", i, got, err)
		}
		if !isProbing(g) {
			t.Fatalf("dial %d: no re-test running", i)
		}
	}
	close(block)
	waitRounds(t, g, 2)
	time.Sleep(30 * ms_)
	if n := g.roundsRun.Load(); n != 2 || isProbing(g) {
		t.Fatalf("rounds %d probing=%v, want exactly one re-test", n, isProbing(g))
	}
	if p.count("a") != 2 || g.Current() != "b" {
		t.Fatalf("probes a=%d current %q", p.count("a"), g.Current())
	}
}

// ---- not immediate: still 3 failures within 60s ----

func TestURLTestRefusalNotImmediate(t *testing.T) {
	under := direct.New(direct.Options{})
	fakeErr := func(typ string, err error) func(t *testing.T) outbound.Outbound {
		return func(t *testing.T) outbound.Outbound {
			f := newFake("a")
			f.typ = typ
			f.setErr(err)
			return f
		}
	}
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) outbound.Outbound
		host  string // destination; empty = a closed loopback port
	}{
		// the destination refused a direct member (local ECONNREFUSED, but not a proxy)
		{"direct-destination", func(t *testing.T) outbound.Outbound { return direct.New(direct.Options{}) }, ""},
		// a nested group whose member is direct
		{"nested-group-direct", func(t *testing.T) outbound.Outbound {
			sg, err := New(Options{Name: "a", Type: TypeSelect, Members: []string{"direct"}}, members(direct.New(direct.Options{})), nil)
			return mustOut(t, sg, err)
		}, ""},
		// the SOCKS5 proxy was reached and reports "connection refused" (reply 5)
		{"socks5-reply-5", func(t *testing.T) outbound.Outbound { return socksOut(t, "a", socksReplyServer(t, 5), under) }, "x.test"},
		// AnyTLS server refused the stream (error shape of anytls/stream.go;
		// the server's text may itself say "connection refused")
		{"anytls-server-refused-stream", fakeErr("anytls",
			fmt.Errorf("anytls: server refused stream: %s", "dial tcp 127.0.0.1:9: connect: connection refused")), "x.test"},
		// chain: the first hop (SOCKS5) relays that the member's server refused
		{"chain-relayed-refusal", func(t *testing.T) outbound.Outbound {
			return trojanOut(t, "a", 443, socksOut(t, "hop", socksReplyServer(t, 5), under))
		}, "x.test"},
		// ECONNREFUSED wrapped without a local dial (no *net.OpError)
		{"errno-without-local-dial", fakeErr("socks5", fmt.Errorf("relay: %w", syscall.ECONNREFUSED)), "x.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.build(t), newFake("b")
			dst := outbound.Addr{Host: tc.host, Port: 443}
			if tc.host == "" {
				dst = outbound.Addr{Host: "127.0.0.1", Port: closedPort(t)}
			}
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{a.Name(): 50 * ms_, "b": 100 * ms_})
			ev := &eventLog{}
			g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, ev)
			g.Start(context.Background())
			probeNow(t, g)
			if g.Current() != a.Name() {
				t.Fatalf("current %q", g.Current())
			}
			for k := 1; k <= 2; k++ {
				got, err := dialTo(g, dst)
				if err != nil || got != "b" {
					t.Fatalf("dial %d via %q err %v, want retried on b", k, got, err)
				}
				time.Sleep(20 * ms_)
				if n := g.roundsRun.Load(); n != 1 || isProbing(g) {
					t.Fatalf("failure %d triggered a re-test (rounds %d)", k, n)
				}
				if s := snapMember(g, a.Name()); s.Failures != k {
					t.Fatalf("failures in window %d, want %d", s.Failures, k)
				}
				clk.Advance(5 * time.Second)
			}
			// the unchanged rule: the third failure within 60s re-tests
			if _, err := dialTo(g, dst); err != nil {
				t.Fatal(err)
			}
			waitRounds(t, g, 2)
			if len(switches(ev)) != 0 { // probes still succeed: no switch
				t.Fatalf("switches %v", switches(ev))
			}
		})
	}
}

// Trojan/SS with a wrong credential: dial succeeds, the server closes after
// the first write with zero bytes back. A real failure, not an immediate re-test.
func TestURLTestWriteThenCloseNotImmediate(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	a.typ = "trojan"
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 100 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	probeNow(t, g)
	for k := 1; k <= 2; k++ {
		c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 443})
		if err != nil || ownerOf(c) != "a" {
			t.Fatalf("dial %d: %v", k, err)
		}
		peer := <-a.peers
		go func() { io.ReadFull(peer, make([]byte, 4)); peer.Close() }()
		c.Write([]byte("data"))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("read succeeded")
		}
		c.Close()
		time.Sleep(20 * ms_)
		if n := g.roundsRun.Load(); n != 1 || snapMember(g, "a").Failures != k {
			t.Fatalf("after %d write-then-close failures: rounds %d failures %d", k, n, snapMember(g, "a").Failures)
		}
	}
}

// fallback keeps its consecutive-failure rule: a refusal is one failure.
func TestFallbackServerRefusedUnchanged(t *testing.T) {
	a, b := socksOut(t, "a", closedPort(t), direct.New(direct.Options{})), newFake("b")
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 100 * ms_})
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	probeNow(t, g)
	dialTo(g, outbound.Addr{Host: "x.test", Port: 443})
	time.Sleep(20 * ms_)
	if g.Current() != "a" || g.roundsRun.Load() != 1 {
		t.Fatalf("after one refusal: current %q rounds %d", g.Current(), g.roundsRun.Load())
	}
	dialTo(g, outbound.Addr{Host: "x.test", Port: 443})
	if g.Current() != "b" || g.roundsRun.Load() != 1 {
		t.Fatalf("after two refusals: current %q rounds %d", g.Current(), g.roundsRun.Load())
	}
}

func TestLocalDialRefused(t *testing.T) {
	_, real := (&net.Dialer{}).Dial("tcp4", "127.0.0.1:"+strconv.Itoa(int(closedPort(t))))
	if real == nil {
		t.Fatal("closed port accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, canceled := (&net.Dialer{}).DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(int(closedPort(t))))
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"net.Dialer refused", real, true},
		{"wrapped", fmt.Errorf("anytls: dial server: %w", real), true},
		{"joined", errors.Join(errors.New("other"), fmt.Errorf("x: %w", real)), true},
		{"bare errno", syscall.ECONNREFUSED, false},
		{"read op", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"dial canceled", canceled, false},
		{"dial other errno", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}, false},
		{"socks5 reply 5", socks5.ReplyError(5), false},
		{"anytls refused text", errors.New("anytls: server refused stream: connect: connection refused"), false},
		{"nil", nil, false},
	} {
		if got := localDialRefused(tc.err); got != tc.want {
			t.Errorf("%s: localDialRefused(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
	if !errors.Is(real, syscall.ECONNREFUSED) {
		t.Fatalf("real refusal %v is not ECONNREFUSED", real)
	}
}
