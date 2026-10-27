package kernel

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/stats"
)

const testAnyTLSPadding = "stop=2\n0=30-30\n1=100-200"

func paddingOption(s string) string {
	b, _ := json.Marshal(s)
	return `,"padding_scheme":` + string(b)
}

func paddingInbound(extra string) string {
	return `{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"fixture-password"` + extra + `}}`
}

// Leading zeroes are valid integer syntax, so these exercise the byte boundary
// without exceeding the parser's line/token/range limits.
func paddingAtLimit() string { return "stop=1\n0=" + strings.Repeat("0", 4085) + "-0" }

func TestAnyTLSPaddingCheckRun(t *testing.T) {
	for _, tc := range []struct{ name, extra, want string }{
		{"omitted", "", A.DefaultPaddingScheme},
		{"empty", paddingOption(""), A.DefaultPaddingScheme},
		{"explicit-default", paddingOption(A.DefaultPaddingScheme), A.DefaultPaddingScheme},
		{"custom", paddingOption(testAnyTLSPadding), testAnyTLSPadding},
		{"4096-bytes", paddingOption(paddingAtLimit()), paddingAtLimit()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"inbounds":[` + paddingInbound(tc.extra) + `]}`
			c, e := Load(writeConfig(t, body)) // the kat check path
			if e != nil || c.Inbounds[0].AnyTLS.PaddingScheme != tc.want {
				t.Fatalf("check effective scheme: %v", e)
			}
			s, e := Start(c) // re-validation and the real codec preparation path
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close(context.Background())
			if in := s.cfg.Inbounds[0]; in.anytlsServer == nil || in.anytlsConf.PaddingScheme != tc.want {
				t.Fatal("effective scheme not wired into codec config")
			}
		})
	}
	for _, tc := range []struct{ name, scheme string }{
		{"syntax", "stop=2\n0=30-20"},
		{"missing-stop", "0=30-30"},
		{"duplicate", "stop=2\n0=30-30\n0=40-40"},
		{"outside-stop", "stop=1\n1=30-30"},
		{"4097-bytes", paddingAtLimit() + "0"},
		{"invalid-utf8", "stop=1\n0=0-" + string([]byte{0xff})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := Load(writeConfig(t, `{"inbounds":[`+paddingInbound(paddingOption(tc.scheme))+`]}`)); e == nil {
				t.Fatal("check accepted invalid padding")
			}
			c := Config{Inbounds: []Inbound{{Protocol: "anytls", Listen: "127.0.0.1:0", AnyTLS: &AnyTLSOptions{Password: "p", PaddingScheme: tc.scheme}}}}
			if s, e := Start(c); e == nil {
				s.Close(context.Background())
				t.Fatal("Start accepted invalid padding without Load")
			}
		})
	}
	if _, e := decodeConfig([]byte(`{"inbounds":[` + paddingInbound(`,"padding_scheme":12`) + `]}`)); e == nil {
		t.Fatal("non-string scheme accepted")
	}
	b, _ := json.Marshal(AnyTLSOptions{Password: "p"})
	if bytes.Contains(b, []byte("padding_scheme")) {
		t.Fatal("empty padding field must be omitted when marshaled")
	}
}

func TestAnyTLSPaddingSharedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		ok         bool
	}{
		{"omitted-empty", "", paddingOption(""), true},
		{"omitted-default", "", paddingOption(A.DefaultPaddingScheme), true},
		{"same-custom", paddingOption(testAnyTLSPadding), paddingOption(testAnyTLSPadding), true},
		{"different-padding", "", paddingOption(testAnyTLSPadding), false},
		{"different-custom", paddingOption(testAnyTLSPadding), paddingOption("stop=1\n0=1-1"), false},
		{"different-budget", paddingOption(testAnyTLSPadding), paddingOption(testAnyTLSPadding) + `,"max_streams":8`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := Load(writeConfig(t, `{"inbounds":[`+paddingInbound(tc.a)+`,`+paddingInbound(tc.b)+`]}`))
			if (e == nil) != tc.ok {
				t.Fatalf("check shared identity: %v", e)
			}
			if !tc.ok {
				if s, e := Start(c); e == nil {
					s.Close(context.Background())
					t.Fatal("Start accepted conflicting identity settings")
				}
				return
			}
			s, e := Start(c)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close(context.Background())
			if s.cfg.Inbounds[0].anytlsServer != s.cfg.Inbounds[1].anytlsServer {
				t.Fatal("same identity did not share codec/budgets")
			}
		})
	}
}

// Reads are deliberately strict: unlike atPayload, this must not silently
// consume a cmdPadding and thereby hide an unsolicited update.
func atPaddingPayload(t *testing.T, c net.Conn, id uint32, want string) {
	t.Helper()
	var got []byte
	for len(got) < len(want) {
		cmd, sid, b := atRead(t, c)
		if sid != id || (cmd != 2 && cmd != 7) || (cmd == 7 && len(b) != 0) {
			t.Fatalf("unexpected frame (including padding): cmd=%d id=%d body=%q", cmd, sid, b)
		}
		if cmd == 2 {
			got = append(got, b...)
		}
	}
	if string(got) != want {
		t.Fatalf("payload: %q, want %q", got, want)
	}
}

func atPaddingBarrier(t *testing.T, c net.Conn) {
	t.Helper()
	if e := writeAll(c, atFrame(8, 0, nil)); e != nil {
		t.Fatal(e)
	}
	cmd, id, b := atRead(t, c)
	if cmd != 9 || id != 0 || len(b) != 0 {
		t.Fatalf("unexpected update before heartbeat: %d %d %q", cmd, id, b)
	}
}

func atPaddingLogin(t *testing.T, c net.Conn, version int, password, clientScheme, serverScheme string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	sum := sha256.Sum256([]byte(password))
	md := md5.Sum([]byte(clientScheme))
	p := append(sum[:], 0, 0)
	p = append(p, atFrame(4, 0, []byte(fmt.Sprintf("v=%d\nclient=kat-padding-test\npadding-md5=%s", version, hex.EncodeToString(md[:]))))...)
	if e := writeAll(c, p); e != nil {
		t.Fatal(e)
	}
	if version == 2 {
		cmd, id, b := atRead(t, c)
		if cmd != 10 || id != 0 || string(b) != "v=2" {
			t.Fatalf("server settings: %d %d %q", cmd, id, b)
		}
	}
	if clientScheme != serverScheme {
		cmd, id, b := atRead(t, c)
		if cmd != 6 || id != 0 || string(b) != serverScheme {
			t.Fatalf("exact padding update: %d %d %q", cmd, id, b)
		}
	}
	if version == 2 {
		atPaddingBarrier(t, c) // also proves no (duplicate) update on a match
	}
}

func TestAnyTLSPaddingTLSNegotiation(t *testing.T) {
	cert, roots := testCert(t)
	for _, version := range []int{1, 2} {
		for _, match := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/match=%v", version, match), func(t *testing.T) {
				in := anyIn(cert)
				in.AnyTLS.PaddingScheme = testAnyTLSPadding
				s := startTest(t, in, nil)
				c := dialPeer(t, s, roots) // actual TLS, not net.Pipe
				clientScheme := A.DefaultPaddingScheme
				if match {
					clientScheme = testAnyTLSPadding
				}
				atPaddingLogin(t, c, version, in.AnyTLS.Password, clientScheme, testAnyTLSPadding)
				atOpen(t, c, 1, echoTCP(t), []byte("custom-padding-tcp"))
				atPaddingPayload(t, c, 1, "custom-padding-tcp") // v1 also proves no extra cmdPadding
				udp := localUDP(t)
				a := addrFromNet(udp.LocalAddr())
				if e := writeAll(c, append(atFrame(1, 2, nil), atFrame(2, 2, atUDPHeader(a, match))...)); e != nil {
					t.Fatal(e)
				}
				atUDPEcho(t, c, 2, udp, match, "custom-padding-udp")
				if e := writeAll(c, append(atFrame(3, 1, nil), atFrame(3, 2, nil)...)); e != nil {
					t.Fatal(e)
				}
				waitFor(t, func() bool { return s.logical.Load() == 0 && s.Stats().UDP == 0 })
				c.Close()
				waitFor(t, func() bool { return s.Stats().Active == 0 })
			})
		}
	}
}

func TestAnyTLSPaddingReloadDefaultEquivalence(t *testing.T) {
	cert, roots := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	base := socksCfg()
	base.Inbounds = []Inbound{in}
	next := base
	s := startReloadable(t, base, &next)
	codec, auth := s.cfg.Inbounds[0].anytlsServer, s.cfg.Inbounds[0].anytlsAuth
	c := atBegin(t, s, roots, 2, in.Listen)
	for _, scheme := range []string{A.DefaultPaddingScheme, "", A.DefaultPaddingScheme} {
		next.Inbounds = append([]Inbound(nil), base.Inbounds...)
		o := *in.AnyTLS
		o.PaddingScheme = scheme
		next.Inbounds[0].AnyTLS = &o
		if _, e := s.Reload("padding-default-equivalence"); e != nil {
			t.Fatal(e)
		}
		g := s.current()
		if g.cfg.Inbounds[0].anytlsServer != codec || g.cfg.Inbounds[0].anytlsAuth != auth {
			t.Fatal("equivalent default changed codec or authority")
		}
		atPaddingBarrier(t, c)
	}
}

func TestAnyTLSPaddingReloadCarriers(t *testing.T) {
	cert, roots := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	base := socksCfg()
	base.Limits.UDPIdle = Duration(10 * time.Second)
	base.Inbounds = []Inbound{in}
	next := base
	s := startReloadable(t, base, &next)
	// Follow the actual decode -> Validate path on reload, not just a prepared struct.
	s.SetConfigLoader(func() (Config, error) {
		b, e := json.Marshal(next)
		if e != nil {
			return Config{}, e
		}
		return decodeConfig(b)
	})
	old := atBegin(t, s, roots, 2, in.Listen)
	old.SetDeadline(time.Now().Add(8 * time.Second))
	pending := atTLS(t, in.Listen, roots) // accepted before reload, settings sent afterwards
	target, udp := echoTCP(t), localUDP(t)
	ua := addrFromNet(udp.LocalAddr())
	atOpen(t, old, 1, target, []byte("tcp-before"))
	atPaddingPayload(t, old, 1, "tcp-before")
	if e := writeAll(old, append(atFrame(1, 2, nil), atFrame(2, 2, atUDPHeader(ua, true))...)); e != nil {
		t.Fatal(e)
	}
	atUDPEcho(t, old, 2, udp, true, "udp-before")
	codec, auth := s.cfg.Inbounds[0].anytlsServer, s.cfg.Inbounds[0].anytlsAuth
	ln := s.core.tcpEntries[listenKey(in.Listen)].ln
	next.Inbounds = append([]Inbound(nil), base.Inbounds...)
	o := *in.AnyTLS
	o.PaddingScheme = testAnyTLSPadding
	next.Inbounds[0].AnyTLS = &o
	if _, e := s.Reload("padding-change"); e != nil {
		t.Fatal(e)
	}
	g := s.current()
	if g.cfg.Inbounds[0].anytlsServer == codec || g.cfg.Inbounds[0].anytlsConf.PaddingScheme != testAnyTLSPadding || g.cfg.Inbounds[0].anytlsAuth != auth || s.core.tcpEntries[listenKey(in.Listen)].ln != ln {
		t.Fatal("padding must change codec only, preserving listener and authority")
	}
	atPaddingBarrier(t, old) // no hot broadcast
	atPaddingLogin(t, pending, 2, in.AnyTLS.Password, A.DefaultPaddingScheme, A.DefaultPaddingScheme)
	pending.Close()
	atOpen(t, old, 3, target, []byte("old-carrier-new-stream"))
	atPaddingPayload(t, old, 3, "old-carrier-new-stream")
	if e := writeAll(old, append(atFrame(1, 4, nil), atFrame(2, 4, atUDPHeader(ua, false))...)); e != nil {
		t.Fatal(e)
	}
	atUDPEcho(t, old, 4, udp, false, "old-carrier-new-udp")
	if v := s.StatsView().Reload; len(v.Retained) != 1 || v.Retained[0].Generation != 1 || v.Retained[0].References != 2 || g.refs.Load() != 3 {
		t.Fatalf("old carrier's new stream must reference current routing generation: %+v current refs=%d", v, g.refs.Load())
	}
	if codec.Stats().Streams != 4 || g.cfg.Inbounds[0].anytlsServer.Stats().Streams != 0 {
		t.Fatal("old carrier's new stream did not stay on its old codec")
	}
	if e := writeAll(old, atFrame(2, 1, []byte("tcp-after"))); e != nil {
		t.Fatal(e)
	}
	atPaddingPayload(t, old, 1, "tcp-after")
	atUDPEcho(t, old, 2, udp, true, "udp-after")
	for _, clientScheme := range []string{A.DefaultPaddingScheme, testAnyTLSPadding} {
		fresh := atTLS(t, in.Listen, roots)
		atPaddingLogin(t, fresh, 2, in.AnyTLS.Password, clientScheme, testAnyTLSPadding)
		atOpen(t, fresh, 1, target, []byte("fresh"))
		atPaddingPayload(t, fresh, 1, "fresh")
		fresh.Close()
		waitFor(t, func() bool { return g.cfg.Inbounds[0].anytlsServer.Stats().Sessions == 0 })
	}
	atPaddingBarrier(t, old)
	for id := uint32(1); id <= 4; id++ {
		if e := writeAll(old, atFrame(3, id, nil)); e != nil {
			t.Fatal(e)
		}
	}
	waitFor(t, func() bool { return s.logical.Load() == 0 && s.Stats().UDP == 0 && codec.Stats().Streams == 0 })
	old.Close()
	waitFor(t, func() bool {
		return s.Stats().Active == 0 && s.logical.Load() == 0 && s.Stats().UDP == 0 && codec.Stats().Sessions == 0 && s.StatsView().Reload.LiveGenerations == 1
	})
}

func TestAnyTLSPaddingInvalidReloadUnchanged(t *testing.T) {
	cert, roots := testCert(t)
	dir := t.TempDir()
	base := selectCfg(filepath.Join(dir, "old.stats.json"), "", "direct", "reject", "h")
	base.API = &APIOptions{Socket: filepath.Join(dir, "old.sock"), Listen: reloadPort(t), Secret: "old-padding-api-secret"}
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	base.Inbounds = []Inbound{in}
	base.Limits.UDPIdle = Duration(10 * time.Second)
	next := base
	s := startReloadable(t, base, &next)
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	old := s.current()
	codec, auth := old.cfg.Inbounds[0].anytlsServer, old.cfg.Inbounds[0].anytlsAuth
	ln := s.core.tcpEntries[listenKey(in.Listen)].ln
	carrier := atBegin(t, s, roots, 2, in.Listen)
	carrier.SetDeadline(time.Now().Add(10 * time.Second))
	target := echoTCP(t)
	atOpen(t, carrier, 1, target, []byte("before"))
	atPaddingPayload(t, carrier, 1, "before")
	udp := localUDP(t)
	ua := addrFromNet(udp.LocalAddr())
	if e := writeAll(carrier, append(atFrame(1, 2, nil), atFrame(2, 2, atUDPHeader(ua, true))...)); e != nil {
		t.Fatal(e)
	}
	atUDPEcho(t, carrier, 2, udp, true, "udp-before")
	s.reg.Total.AddUp(12345)
	s.saveStats()
	oldBytes, e := os.ReadFile(base.Stats.File)
	if e != nil {
		t.Fatal(e)
	}
	oldSel, e := os.ReadFile(selectStatePath(base.Stats.File))
	if e != nil {
		t.Fatal(e)
	}
	api := atomicClient(t, "")
	url := "http://" + base.API.Listen + "/v1/version"
	for i, scheme := range []string{"stop=0", paddingAtLimit() + "0"} {
		for _, decode := range []bool{false, true} {
			next = base
			next.Inbounds = append([]Inbound(nil), base.Inbounds...)
			o := *in.AnyTLS
			o.PaddingScheme, o.Password = scheme, "candidate-password"
			next.Inbounds[0].AnyTLS = &o
			next.API = &APIOptions{Socket: filepath.Join(dir, "new.sock"), Listen: reloadPort(t), Secret: "new-padding-api-secret"}
			next.Stats = &StatsOptions{File: filepath.Join(dir, "new.stats.json")}
			next.Groups = selectCfg("", "reject", "direct", "reject").Groups
			stage := "validate"
			if decode {
				s.SetConfigLoader(func() (Config, error) {
					b, e := json.Marshal(next)
					if e != nil {
						return Config{}, e
					}
					return decodeConfig(b)
				})
				stage = "load"
			} else {
				s.SetConfigLoader(func() (Config, error) { return next, nil })
			}
			_, e := s.Reload("invalid-padding")
			var re *ReloadError
			if !errors.As(e, &re) || re.Stage != stage {
				t.Fatalf("invalid padding reload: %v", e)
			}
			if s.current() != old || s.core.genSeq.Load() != 1 || old.cfg.Inbounds[0].anytlsServer != codec || old.cfg.Inbounds[0].anytlsAuth != auth || s.core.tcpEntries[listenKey(in.Listen)].ln != ln {
				t.Fatal("invalid reload changed generation/codec/authority/listener")
			}
			if s.persistedPath() != base.Stats.File || s.reg.Snapshot().Total.Up < 12345 {
				t.Fatal("stats changed")
			}
			b, _ := os.ReadFile(base.Stats.File)
			sel, _ := os.ReadFile(selectStatePath(base.Stats.File))
			if !bytes.Equal(b, oldBytes) || !bytes.Equal(sel, oldSel) {
				t.Fatal("stats/select files changed")
			}
			if cur, _ := currentOf(t, s, "g"); cur != "h" {
				t.Fatal("runtime selection changed")
			}
			if unlock, e := stats.Lock(base.Stats.File); e == nil {
				unlock()
				t.Fatal("old stats lock lost")
			}
			for _, path := range []string{next.API.Socket, next.Stats.File, selectStatePath(next.Stats.File)} {
				if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("candidate target created: %s: %v", path, e)
				}
			}
			if code, _ := atomicRequest(t, api, url, "GET", base.API.Secret); code != 200 {
				t.Fatal("old API/auth stopped", code)
			}
			if code, _ := atomicRequest(t, api, url, "GET", next.API.Secret); code != 401 {
				t.Fatal("new API secret installed", code)
			}
			atPaddingBarrier(t, carrier)
			id := uint32(3 + i*2)
			if decode {
				id++
			}
			atOpen(t, carrier, id, target, []byte("still-authorized"))
			atPaddingPayload(t, carrier, id, "still-authorized")
			if e := writeAll(carrier, atFrame(3, id, nil)); e != nil {
				t.Fatal(e)
			}
			waitFor(t, func() bool { return s.logical.Load() == 2 })
			if e := writeAll(carrier, atFrame(2, 1, []byte("tcp-after-refusal"))); e != nil {
				t.Fatal(e)
			}
			atPaddingPayload(t, carrier, 1, "tcp-after-refusal")
			atUDPEcho(t, carrier, 2, udp, true, "udp-after-refusal")
			fresh := atBegin(t, s, roots, 2, in.Listen)
			atPaddingBarrier(t, fresh)
			fresh.Close()
			waitFor(t, func() bool { return codec.Stats().Sessions == 1 })
		}
	}
	if e := writeAll(carrier, atFrame(2, 1, []byte("established-survives"))); e != nil {
		t.Fatal(e)
	}
	atPaddingPayload(t, carrier, 1, "established-survives")
	next = base
	s.SetConfigLoader(func() (Config, error) { return next, nil })
	if r, e := s.Reload("after-invalid-padding"); e != nil || r.Generation != 2 {
		t.Fatalf("failures consumed generation: %+v %v", r, e)
	}
	if e := writeAll(carrier, append(atFrame(3, 1, nil), atFrame(3, 2, nil)...)); e != nil {
		t.Fatal(e)
	}
	waitFor(t, func() bool { return s.logical.Load() == 0 && s.Stats().UDP == 0 })
	carrier.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
}
