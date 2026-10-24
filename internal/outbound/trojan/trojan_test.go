package trojan_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/internal/proxytest"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
)

const password = "trojan-outbound-pass"

func opts(port int, tls *outbound.TLSOptions) outbound.Options {
	return outbound.Options{Name: "tr", Type: "trojan", Server: "127.0.0.1", Port: uint16(port), Password: password, TLS: tls}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	cert := proxytest.SelfSigned(t, dir)
	f := false
	good := []outbound.Options{
		opts(443, &outbound.TLSOptions{}),
		opts(443, &outbound.TLSOptions{CA: cert.CertPath, ServerName: "localhost", ALPN: []string{"h2", "http/1.1"}}),
		opts(443, &outbound.TLSOptions{PinSHA256: strings.ToUpper(cert.PinSHA256)}),
		opts(443, &outbound.TLSOptions{Insecure: true}),
		{Name: "x", Type: "trojan", Server: "proxy.example.com", Port: 1, Password: "p", TLS: &outbound.TLSOptions{}, UDP: &f, Via: "hop"},
	}
	for i, o := range good {
		if e := trojan.Validate(o); e != nil {
			t.Errorf("good %d: %v", i, e)
		}
	}
	junk := filepath.Join(dir, "junk.pem")
	os.WriteFile(junk, []byte("not a cert"), 0600)
	mut := func(f func(*outbound.Options)) outbound.Options {
		o := opts(443, &outbound.TLSOptions{})
		f(&o)
		return o
	}
	bad := []outbound.Options{
		mut(func(o *outbound.Options) { o.Type = "trojan-go" }),
		mut(func(o *outbound.Options) { o.Name = "" }),
		mut(func(o *outbound.Options) { o.Server = "under_score..bad" }),
		mut(func(o *outbound.Options) { o.Port = 0 }),
		mut(func(o *outbound.Options) { o.Password = "" }),
		mut(func(o *outbound.Options) { o.Password = strings.Repeat("p", 4097) }),
		mut(func(o *outbound.Options) { o.TLS = nil }),
		mut(func(o *outbound.Options) { o.Username = "u" }),
		mut(func(o *outbound.Options) { o.Method = "aes-128-gcm" }),
		mut(func(o *outbound.Options) { o.Key = "k" }),
		mut(func(o *outbound.Options) { o.IdleSessions = 1 }),
		mut(func(o *outbound.Options) { o.IdleTimeout = 1 }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{Insecure: true, PinSHA256: cert.PinSHA256} }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{Insecure: true, CA: cert.CertPath} }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{PinSHA256: "abcd"} }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{CA: filepath.Join(dir, "missing.pem")} }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{CA: junk} }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "bad name"} }),
		mut(func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ALPN: []string{""}} }),
	}
	for i, o := range bad {
		if e := trojan.Validate(o); e == nil {
			t.Errorf("bad %d accepted: %+v", i, o)
		}
		if _, e := trojan.New(o, direct.New(direct.Options{})); e == nil {
			t.Errorf("bad %d: New accepted", i)
		}
	}
	tr, _ := trojan.New(opts(1, &outbound.TLSOptions{}), proxytest.TCPOnly{Under: direct.New(direct.Options{})})
	if !tr.UDP() {
		t.Error("trojan UDP (UoT) must not depend on under.UDP()")
	}
	o := opts(1, &outbound.TLSOptions{})
	o.UDP = &f
	tr, _ = trojan.New(o, direct.New(direct.Options{}))
	if tr.UDP() {
		t.Error("udp:false ignored")
	}
	if _, e := tr.ListenPacket(context.Background()); e != outbound.ErrUDPUnsupported {
		t.Error(e)
	}
}

type server struct {
	name  string
	start func(*testing.T, proxytest.Cert) int
}

var servers = []server{
	{"singbox", func(t *testing.T, c proxytest.Cert) int {
		return proxytest.StartSingBox(t, map[string]any{"type": "trojan", "users": []any{map[string]any{"name": "u", "password": password}},
			"tls": map[string]any{"enabled": true, "certificate_path": c.CertPath, "key_path": c.KeyPath}})
	}},
	{"kat", func(t *testing.T, c proxytest.Cert) int {
		return proxytest.StartKat(t, map[string]any{"protocol": "trojan", "users": []any{map[string]any{"password": password}},
			"tls": map[string]any{"cert": c.CertPath, "key": c.KeyPath}})
	}},
}

func TestInterop(t *testing.T) {
	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			cert := proxytest.SelfSigned(t, t.TempDir())
			port := srv.start(t, cert)
			modes := []struct {
				name string
				tls  *outbound.TLSOptions
			}{
				{"ca", &outbound.TLSOptions{CA: cert.CertPath}},
				{"ca-servername", &outbound.TLSOptions{CA: cert.CertPath, ServerName: "localhost"}},
				{"pin", &outbound.TLSOptions{PinSHA256: cert.PinSHA256}},
				{"insecure", &outbound.TLSOptions{Insecure: true}},
			}
			for _, m := range modes {
				tr, e := trojan.New(opts(port, m.tls), direct.New(direct.Options{}))
				if e != nil {
					t.Fatal(e)
				}
				proxytest.TCPEcho(t, tr, proxytest.EchoTCP(t), 200000)
				proxytest.UDPEcho(t, tr, proxytest.EchoUDP(t, "udp4"))
				t.Logf("PASS %s trojan tls=%s TCP echo + UDP echo", srv.name, m.name)
			}
			// Negative cases: each must fail with an error within its bound.
			other := proxytest.SelfSigned(t, t.TempDir())
			negatives := []struct {
				name string
				o    outbound.Options
			}{
				{"default-mode-self-signed", opts(port, &outbound.TLSOptions{})},
				{"pin-mismatch", opts(port, &outbound.TLSOptions{PinSHA256: other.PinSHA256})},
				{"wrong-ca", opts(port, &outbound.TLSOptions{CA: other.CertPath})},
				{"wrong-password", func() outbound.Options {
					o := opts(port, &outbound.TLSOptions{PinSHA256: cert.PinSHA256})
					o.Password = "wrong-password"
					return o
				}()},
			}
			for _, n := range negatives {
				tr, e := trojan.New(n.o, direct.New(direct.Options{}))
				if e != nil {
					t.Fatal(e)
				}
				start := time.Now()
				e = proxytest.TryTCPEcho(tr, proxytest.EchoTCP(t), 100, 3*time.Second)
				if e == nil {
					t.Fatalf("%s: TCP echo succeeded", n.name)
				}
				if time.Since(start) > 5*time.Second {
					t.Fatalf("%s: not bounded", n.name)
				}
				t.Logf("%s rejected after %v: %v", n.name, time.Since(start).Round(time.Millisecond), e)
				start = time.Now()
				if e = proxytest.TryUDPEcho(tr, proxytest.EchoUDP(t, "udp4"), 2*time.Second); e == nil {
					t.Fatalf("%s: UDP echo succeeded", n.name)
				}
				t.Logf("%s UDP rejected after %v: %v", n.name, time.Since(start).Round(time.Millisecond), e)
			}
		})
	}
}

// (a) trojan over shadowsocks: two hops, TCP echo; the first hop only ever
// dials the shadowsocks server.
func TestChainTrojanOverSS(t *testing.T) {
	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			cert := proxytest.SelfSigned(t, t.TempDir())
			tport := srv.start(t, cert)
			var sport int
			m := "2022-blake3-aes-256-gcm"
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
			if srv.name == "singbox" {
				sport = proxytest.StartSingBox(t, map[string]any{"type": "shadowsocks", "method": m, "password": key})
			} else {
				sport = proxytest.StartKat(t, map[string]any{"protocol": "shadowsocks", "ss": map[string]any{"method": m, "key": key}})
			}
			counter := &proxytest.Counter{Under: direct.New(direct.Options{})}
			s, e := ss.New(outbound.Options{Name: "hop1", Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(sport), Method: m, Key: key}, counter)
			if e != nil {
				t.Fatal(e)
			}
			tr, e := trojan.New(opts(tport, &outbound.TLSOptions{CA: cert.CertPath}), s)
			if e != nil {
				t.Fatal(e)
			}
			proxytest.TCPEcho(t, tr, proxytest.EchoTCP(t), 100000)
			proxytest.UDPEcho(t, tr, proxytest.EchoUDP(t, "udp4")) // UoT over the SS TCP hop
			tcp, udp, lists := counter.Snapshot()
			if len(tcp) != 2 || lists != 0 || len(udp) != 0 {
				t.Fatalf("first hop saw tcp=%v lists=%d udp=%v", tcp, lists, udp)
			}
			for _, a := range tcp {
				if a.Port != uint16(sport) {
					t.Fatalf("first hop dialed %v, want only the SS server", a)
				}
			}
			t.Logf("PASS %s: trojan over SS(%s) TCP echo + UoT UDP echo; first-hop dials=%v", srv.name, m, tcp)
		})
	}
}

// A server that accepts and never answers: the TLS handshake is bounded by ctx.
func TestHandshakeBoundedByContext(t *testing.T) {
	tr, _ := trojan.New(opts(proxytest.Blackhole(t), &outbound.TLSOptions{Insecure: true}), direct.New(direct.Options{}))
	for _, op := range []string{"tcp", "udp"} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		var e error
		if op == "tcp" {
			var c interface{ Close() error }
			if c, e = tr.DialTCP(ctx, outbound.Addr{Host: "example.com", Port: 80}); e == nil {
				c.Close()
			}
		} else {
			var pc outbound.PacketConn
			if pc, e = tr.ListenPacket(ctx); e == nil {
				pc.Close()
			}
		}
		cancel()
		if e == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("%s: err=%v after %v", op, e, time.Since(start))
		}
		t.Logf("%s against silent server: %v after %v", op, e, time.Since(start).Round(time.Millisecond))
	}
}
