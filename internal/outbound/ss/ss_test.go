package ss_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/internal/proxytest"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
)

var methods = []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}

func keyFor(method string, fill byte) string {
	n := 32
	if strings.Contains(method, "128") {
		n = 16
	}
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n))
}

// opts returns client options; secret is a password (2017) or a key seed byte (2022).
func opts(method string, port int, wrong bool) outbound.Options {
	o := outbound.Options{Name: "ss", Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(port), Method: method}
	if strings.HasPrefix(method, "2022-") {
		fill := byte(0x42)
		if wrong {
			fill = 0x43
		}
		o.Key = keyFor(method, fill)
	} else {
		o.Password = "kat-ss-outbound-pass"
		if wrong {
			o.Password = "not-the-password"
		}
	}
	return o
}

func serverSecret(method string) string {
	if strings.HasPrefix(method, "2022-") {
		return keyFor(method, 0x42)
	}
	return "kat-ss-outbound-pass"
}

func singBoxSS(t *testing.T, method string) int {
	return proxytest.StartSingBox(t, map[string]any{"type": "shadowsocks", "method": method, "password": serverSecret(method)})
}

func katSS(t *testing.T, method string) int {
	o := map[string]any{"method": method}
	if strings.HasPrefix(method, "2022-") {
		o["key"] = serverSecret(method)
	} else {
		o["password"] = serverSecret(method)
	}
	return proxytest.StartKat(t, map[string]any{"protocol": "shadowsocks", "ss": o})
}

func TestValidate(t *testing.T) {
	f := false
	for _, m := range methods {
		o := opts(m, 8388, false)
		o.UDP, o.Via = &f, "hop"
		if e := ss.Validate(o); e != nil {
			t.Errorf("%s: %v", m, e)
		}
	}
	base := func(mut func(*outbound.Options)) outbound.Options {
		o := opts("2022-blake3-aes-128-gcm", 8388, false)
		mut(&o)
		return o
	}
	base17 := func(mut func(*outbound.Options)) outbound.Options {
		o := opts("aes-256-gcm", 8388, false)
		mut(&o)
		return o
	}
	bad := []outbound.Options{
		base(func(o *outbound.Options) { o.Type = "ss" }),
		base(func(o *outbound.Options) { o.Name = "" }),
		base(func(o *outbound.Options) { o.Server = "" }),
		base(func(o *outbound.Options) { o.Server = "a..b" }),
		base(func(o *outbound.Options) { o.Port = 0 }),
		base(func(o *outbound.Options) { o.Method = "rc4-md5" }),
		base(func(o *outbound.Options) { o.Method = "2022-blake3-aes-256-gcm" }), // 16-byte key for 32-byte method
		base(func(o *outbound.Options) { o.Key = o.Key + ":" + o.Key }),          // EIH
		base(func(o *outbound.Options) { o.Key = "not base64!" }),
		base(func(o *outbound.Options) { o.Password = "x" }),
		base(func(o *outbound.Options) { o.Username = "u" }),
		base(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{} }),
		base(func(o *outbound.Options) { o.IdleSessions = 2 }),
		base(func(o *outbound.Options) { o.IdleTimeout = 1 }),
		base17(func(o *outbound.Options) { o.Password = "" }),
		base17(func(o *outbound.Options) { o.Key = keyFor("aes-256-gcm", 1) }),
		base17(func(o *outbound.Options) { o.Password = strings.Repeat("p", 4097) }),
	}
	for i, o := range bad {
		if e := ss.Validate(o); e == nil {
			t.Errorf("bad %d accepted: %+v", i, o)
		}
		if _, e := ss.New(o, direct.New(direct.Options{})); e == nil {
			t.Errorf("bad %d: New accepted", i)
		}
	}
}

func TestInteropSingBox(t *testing.T) {
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			port := singBoxSS(t, m)
			s, e := ss.New(opts(m, port, false), direct.New(direct.Options{}))
			if e != nil {
				t.Fatal(e)
			}
			proxytest.TCPEcho(t, s, proxytest.EchoTCP(t), 200000)
			proxytest.TCPEcho(t, s, proxytest.EchoTCP(t), 1)
			proxytest.UDPEcho(t, s, proxytest.EchoUDP(t, "udp4"))
			t.Logf("PASS sing-box shadowsocks %s TCP echo + UDP echo", m)
			wrongCredential(t, m, port)
		})
	}
}

func TestInteropKat(t *testing.T) {
	for _, m := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(m, func(t *testing.T) {
			port := katSS(t, m)
			s, e := ss.New(opts(m, port, false), direct.New(direct.Options{}))
			if e != nil {
				t.Fatal(e)
			}
			proxytest.TCPEcho(t, s, proxytest.EchoTCP(t), 200000)
			proxytest.TCPEcho(t, s, proxytest.EchoTCP(t), 1)
			proxytest.UDPEcho(t, s, proxytest.EchoUDP(t, "udp4"))
			t.Logf("PASS kat shadowsocks %s TCP echo + UDP echo", m)
			serverFirst(t, s)
			wrongCredential(t, m, port)
		})
	}
}

// serverFirst: a Read before any Write still sends the request (header-only,
// padded for SIP022) so server-first protocols work.
func serverFirst(t *testing.T, s outbound.Dialer) {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("220 banner\r\n"))
		time.Sleep(time.Second)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := s.DialTCP(ctx, outbound.Addr{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	n, e := c.Read(b)
	if e != nil || !strings.HasPrefix(string(b[:n]), "220") {
		t.Fatalf("server-first banner: %q %v", b[:n], e)
	}
	t.Logf("PASS server-first read before write")
}

// wrongCredential: wrong key/password fails (error, not hang) for TCP and UDP.
func wrongCredential(t *testing.T, m string, port int) {
	bad, e := ss.New(opts(m, port, true), direct.New(direct.Options{}))
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	if e := proxytest.TryTCPEcho(bad, proxytest.EchoTCP(t), 100, 3*time.Second); e == nil {
		t.Fatal("wrong credential: TCP echo succeeded")
	} else {
		t.Logf("wrong credential TCP rejected after %v: %v", time.Since(start).Round(time.Millisecond), e)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("wrong credential: not bounded by timeout")
	}
	start = time.Now()
	if e := proxytest.TryUDPEcho(bad, proxytest.EchoUDP(t, "udp4"), 2*time.Second); e == nil {
		t.Fatal("wrong credential: UDP echo succeeded")
	} else {
		t.Logf("wrong credential UDP rejected after %v: %v", time.Since(start).Round(time.Millisecond), e)
	}
}

// (b) SS native UDP over trojan UDP-over-TLS, two hops, and (a') SS TCP over trojan.
func TestChainSSOverTrojan(t *testing.T) {
	for _, srv := range []string{"singbox", "kat"} {
		t.Run(srv, func(t *testing.T) {
			dir := t.TempDir()
			cert := proxytest.SelfSigned(t, dir)
			var tport, sport int
			m := "2022-blake3-aes-128-gcm"
			if srv == "singbox" {
				tport = proxytest.StartSingBox(t, map[string]any{"type": "trojan", "users": []any{map[string]any{"name": "u", "password": "trojan-pass"}},
					"tls": map[string]any{"enabled": true, "certificate_path": cert.CertPath, "key_path": cert.KeyPath}})
				sport = singBoxSS(t, m)
			} else {
				tport = proxytest.StartKat(t, map[string]any{"protocol": "trojan", "users": []any{map[string]any{"password": "trojan-pass"}},
					"tls": map[string]any{"cert": cert.CertPath, "key": cert.KeyPath}})
				sport = katSS(t, m)
			}
			counter := &proxytest.Counter{Under: direct.New(direct.Options{})}
			tr, e := trojan.New(outbound.Options{Name: "tr", Type: "trojan", Server: "127.0.0.1", Port: uint16(tport), Password: "trojan-pass",
				TLS: &outbound.TLSOptions{PinSHA256: cert.PinSHA256}}, counter)
			if e != nil {
				t.Fatal(e)
			}
			s, e := ss.New(opts(m, sport, false), tr)
			if e != nil {
				t.Fatal(e)
			}
			if !s.UDP() {
				t.Fatal("SS over trojan must support UDP")
			}
			proxytest.UDPEcho(t, s, proxytest.EchoUDP(t, "udp4"))
			proxytest.TCPEcho(t, s, proxytest.EchoTCP(t), 50000)
			tcp, udp, lists := counter.Snapshot()
			if lists != 0 || len(udp) != 0 {
				t.Fatalf("first hop sent native UDP: lists=%d udp=%v", lists, udp)
			}
			for _, a := range tcp {
				if a.Port != uint16(tport) {
					t.Fatalf("first hop dialed %v, want only the trojan server", a)
				}
			}
			t.Logf("PASS %s: SS(%s) UDP over trojan UoT + TCP two hops; first-hop dials=%v", srv, m, tcp)
		})
	}
}

// (c) SS over a TCP-only under: UDP()==false, ListenPacket -> ErrUDPUnsupported.
func TestUDPRequiresUnderUDP(t *testing.T) {
	f := false
	s5, e := socks5.New(outbound.Options{Name: "s5", Type: "socks5", Server: "127.0.0.1", Port: 1080, UDP: &f}, direct.New(direct.Options{}))
	if e != nil {
		t.Fatal(e)
	}
	for _, under := range []outbound.Dialer{s5, proxytest.TCPOnly{Under: direct.New(direct.Options{})}} {
		for _, m := range methods {
			s, e := ss.New(opts(m, 8388, false), under)
			if e != nil {
				t.Fatal(e)
			}
			if s.UDP() {
				t.Fatalf("%s over %T: UDP() true", m, under)
			}
			if _, e = s.ListenPacket(context.Background()); !errors.Is(e, outbound.ErrUDPUnsupported) {
				t.Fatalf("%s over %T: %v", m, under, e)
			}
		}
	}
	o := opts("aes-128-gcm", 8388, false)
	o.UDP = &f
	s, _ := ss.New(o, direct.New(direct.Options{}))
	if s.UDP() {
		t.Fatal("udp:false ignored")
	}
	t.Log("PASS SS over TCP-only under: UDP()==false, ErrUDPUnsupported")
}

// (d) every connection/datagram to the proxy server goes through under.
func TestAllTrafficViaUnder(t *testing.T) {
	m := "2022-blake3-chacha20-poly1305"
	port := singBoxSS(t, m)
	counter := &proxytest.Counter{Under: direct.New(direct.Options{})}
	s, e := ss.New(opts(m, port, false), counter)
	if e != nil {
		t.Fatal(e)
	}
	echoT, echoU := proxytest.EchoTCP(t), proxytest.EchoUDP(t, "udp4")
	proxytest.TCPEcho(t, s, echoT, 1000)
	proxytest.TCPEcho(t, s, echoT, 1000)
	proxytest.UDPEcho(t, s, echoU)
	tcp, udp, lists := counter.Snapshot()
	server := outbound.Addr{Host: "127.0.0.1", Port: uint16(port)}
	if len(tcp) != 2 || lists != 1 || len(udp) < 3 {
		t.Fatalf("under saw tcp=%v lists=%d udp=%d", tcp, lists, len(udp))
	}
	for _, a := range append(tcp, udp...) {
		if a != server {
			t.Fatalf("under asked for %v, want only %v", a, server)
		}
	}
	// A failing under makes the outbound fail: there is no bypass path.
	refuse := &proxytest.Counter{Under: proxytest.TCPOnly{Under: failing{}}}
	s2, _ := ss.New(opts(m, port, false), refuse)
	if e := proxytest.TryTCPEcho(s2, echoT, 10, 2*time.Second); e == nil {
		t.Fatal("dial succeeded although under refuses")
	}
	t.Logf("PASS all proxy traffic via under: tcp=%v datagrams=%d (all to %v)", tcp, len(udp), server)
}

type failing struct{}

func (failing) DialTCP(context.Context, outbound.Addr) (net.Conn, error) {
	return nil, errors.New("under refuses")
}
func (failing) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, errors.New("under refuses")
}
func (failing) UDP() bool { return true }

// A server that accepts and never answers (e.g. one that silently drains
// unauthenticated clients): reads are bounded by the deadline / timeout.
func TestSilentServerBounded(t *testing.T) {
	port := proxytest.Blackhole(t)
	for _, m := range methods {
		s, _ := ss.New(opts(m, port, false), direct.New(direct.Options{}))
		start := time.Now()
		e := proxytest.TryTCPEcho(s, outbound.Addr{Host: "example.com", Port: 80}, 10, 500*time.Millisecond)
		if e == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("%s: err=%v after %v", m, e, time.Since(start))
		}
		t.Logf("%s against silent server: %v after %v", m, e, time.Since(start).Round(time.Millisecond))
	}
}
