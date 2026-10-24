package anytls

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Real-process interop against sing-box's AnyTLS server. Gated by
// KAT_INTEROP_SINGBOX=/path/to/sing-box; run under the shared flock.
// KAT_INTEROP_LOGDIR keeps the sing-box config/log for evidence.

type singBox struct {
	bin, dir string
	port     int
	cmd      *exec.Cmd
	exited   chan struct{}
	starts   int
}

func freePort(t *testing.T) int {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startSingBox(t *testing.T, cert testCert, password string) *singBox {
	bin := os.Getenv("KAT_INTEROP_SINGBOX")
	if bin == "" {
		t.Skip("set KAT_INTEROP_SINGBOX to run sing-box interop")
	}
	dir := os.Getenv("KAT_INTEROP_LOGDIR")
	if dir == "" {
		dir = t.TempDir()
	} else {
		dir = filepath.Join(dir, "singbox-"+strings.ReplaceAll(t.Name(), "/", "_"))
		if e := os.MkdirAll(dir, 0o700); e != nil {
			t.Fatal(e)
		}
	}
	sb := &singBox{bin: bin, dir: dir, port: freePort(t)}
	cfg := map[string]any{
		"log": map[string]any{"level": "debug", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "anytls", "tag": "anytls-in", "listen": "127.0.0.1", "listen_port": sb.port,
			"users": []any{map[string]any{"name": "kat", "password": password}},
			"tls":   map[string]any{"enabled": true, "certificate_path": cert.certFile, "key_path": cert.keyFile},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if e := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600); e != nil {
		t.Fatal(e)
	}
	sb.start(t)
	t.Cleanup(func() { sb.stop(t) })
	return sb
}

func (sb *singBox) start(t *testing.T) {
	sb.starts++
	logf, e := os.Create(filepath.Join(sb.dir, fmt.Sprintf("sing-box-%d.log", sb.starts)))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(sb.bin, "run", "-c", filepath.Join(sb.dir, "config.json"), "-D", sb.dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	if e = cmd.Start(); e != nil {
		logf.Close()
		t.Fatal(e)
	}
	sb.cmd = cmd
	exited := make(chan struct{})
	sb.exited = exited
	t.Logf("sing-box started pid=%d port=%d", cmd.Process.Pid, sb.port)
	go func() { _ = cmd.Wait(); logf.Close(); close(exited) }()
	for i := 0; i < 100; i++ {
		if c, e := net.DialTimeout("tcp", sb.addr().String(), 100*time.Millisecond); e == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sing-box did not listen")
}

// stop kills exactly the process this test started.
func (sb *singBox) stop(t *testing.T) {
	if sb.cmd != nil && sb.cmd.Process != nil {
		t.Logf("killing sing-box pid=%d", sb.cmd.Process.Pid)
		_ = sb.cmd.Process.Kill()
		select {
		case <-sb.exited:
		case <-time.After(5 * time.Second):
			t.Error("sing-box did not exit after kill")
		}
		sb.cmd = nil
	}
}

func (sb *singBox) addr() outbound.Addr {
	return outbound.Addr{Host: "127.0.0.1", Port: uint16(sb.port)}
}

func TestSingBoxInterop(t *testing.T) {
	cert := newTestCert(t)
	const password = "kat-singbox-interop"
	sb := startSingBox(t, cert, password)
	echo := tcpEchoServer(t)

	t.Run("tcp_concurrent_reuse_udp", func(t *testing.T) {
		under := &countingDialer{}
		o := newTestOutbound(t, baseOptions(sb.addr(), password, &outbound.TLSOptions{PinSHA256: cert.pin}), under)
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		if e = echoRoundTrip(c, []byte("hello sing-box")); e != nil {
			t.Fatal(e)
		}
		c.Close()
		waitIdle(t, o, 1)
		c2, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		if e = echoRoundTrip(c2, []byte("reused session")); e != nil {
			t.Fatal(e)
		}
		c2.Close()
		if s, d := o.sessionsCreated.Load(), under.n.Load(); s != 1 || d != 1 {
			t.Fatalf("sessions created=%d under dials=%d, want 1/1 (reuse without new TLS)", s, d)
		}
		t.Logf("TCP: echo, close, re-dial reused the idle session: sessions=%d under dials=%d", o.sessionsCreated.Load(), under.n.Load())
		waitIdle(t, o, 1)
		concurrentEcho(t, o, echo, 8, 256<<10) // one reuses the idle session, 7 new
		if s, d := o.sessionsCreated.Load(), under.n.Load(); s != 8 || d != 8 {
			t.Fatalf("8 concurrent: sessions=%d under dials=%d, want 8/8", s, d)
		}
		waitIdle(t, o, 4) // idle_sessions default bound
		c3, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		if e = echoRoundTrip(c3, []byte("reused after concurrency")); e != nil {
			t.Fatal(e)
		}
		c3.Close()
		if d := under.n.Load(); d != 8 {
			t.Fatalf("re-dial after concurrency dialed under again: %d", d)
		}
		t.Logf("TCP: 8 concurrent streams (256KiB each) on 8 distinct sessions; idle pool 4; re-dial reused; sessions=%d under dials=%d", o.sessionsCreated.Load(), under.n.Load())

		pc, e := o.ListenPacket(ctxTimeout(t, 5*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		defer pc.Close()
		u1, u2 := udpEchoServer(t, "A:"), udpEchoServer(t, "B:")
		udpRoundTrip(t, pc, u1, []byte("uot first target"), "A:")
		udpRoundTrip(t, pc, u2, []byte("uot second target"), "B:")
		udpRoundTrip(t, pc, u1, pattern(3, 1200), "A:")
		udpRoundTrip(t, pc, u2, pattern(4, 8000), "B:")
		if d := under.n.Load(); d != 8 {
			t.Fatalf("UoT should take an idle session; under dials=%d", d)
		}
		t.Logf("UoT v2: replies from %v and %v verified; sessions=%d under dials=%d", u1, u2, o.sessionsCreated.Load(), under.n.Load())
	})

	t.Run("tls_modes", func(t *testing.T) {
		for _, m := range []struct {
			name string
			opt  *outbound.TLSOptions
			ok   bool
		}{
			{"ca", &outbound.TLSOptions{CA: cert.certFile}, true},
			{"pin_sha256", &outbound.TLSOptions{PinSHA256: cert.pin}, true},
			{"insecure", &outbound.TLSOptions{Insecure: true}, true},
			{"default_rejects_self_signed", &outbound.TLSOptions{}, false},
		} {
			o := newTestOutbound(t, baseOptions(sb.addr(), password, m.opt), &countingDialer{})
			c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
			if !m.ok {
				if e == nil {
					c.Close()
					t.Fatalf("%s: accepted", m.name)
				}
				t.Logf("%s: rejected: %v", m.name, e)
				continue
			}
			if e != nil {
				t.Fatalf("%s: %v", m.name, e)
			}
			if e = echoRoundTrip(c, []byte("mode "+m.name)); e != nil {
				t.Fatalf("%s: %v", m.name, e)
			}
			c.Close()
			t.Logf("%s: connected and echoed", m.name)
		}
	})

	t.Run("wrong_password", func(t *testing.T) {
		o := newTestOutbound(t, baseOptions(sb.addr(), "not-the-password", &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
		start := time.Now()
		_, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e == nil {
			t.Fatal("wrong password accepted")
		}
		el := time.Since(start)
		if el > 5500*time.Millisecond {
			t.Fatalf("wrong password not bounded: %v", el)
		}
		t.Logf("wrong password rejected after %v: %v", el.Round(time.Millisecond), e)
	})

	t.Run("synack_failure", func(t *testing.T) {
		o := newTestOutbound(t, baseOptions(sb.addr(), password, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
		closed := freePort(t)
		_, e := o.DialTCP(ctxTimeout(t, 5*time.Second), outbound.Addr{Host: "127.0.0.1", Port: uint16(closed)})
		if e == nil {
			t.Fatal("dial to closed port succeeded")
		}
		t.Logf("unreachable target via sing-box: %v", e)
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal("session unusable after refused stream:", e)
		}
		if e = echoRoundTrip(c, []byte("after refusal")); e != nil {
			t.Fatal(e)
		}
		c.Close()
		if n := o.sessionsCreated.Load(); n != 1 {
			t.Fatalf("refused stream should not kill the session; sessions=%d", n)
		}
	})

	t.Run("server_killed_and_restarted", func(t *testing.T) {
		under := &countingDialer{}
		o := newTestOutbound(t, baseOptions(sb.addr(), password, &outbound.TLSOptions{PinSHA256: cert.pin}), under)
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		if e = echoRoundTrip(c, []byte("before kill")); e != nil {
			t.Fatal(e)
		}
		pc, e := o.ListenPacket(ctxTimeout(t, 5*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		u := udpEchoServer(t, "")
		udpRoundTrip(t, pc, u, []byte("udp before kill"), "")
		sb.stop(t)
		errc := make(chan error, 2)
		go func() { _, e := c.Read(make([]byte, 8)); errc <- e }()
		go func() { _, _, e := pc.ReadFrom(make([]byte, 8)); errc <- e }()
		for i := 0; i < 2; i++ {
			select {
			case e := <-errc:
				if e == nil {
					t.Fatal("read succeeded after server death")
				}
				t.Logf("existing stream after kill: %v", e)
			case <-time.After(5 * time.Second):
				t.Fatal("existing stream hangs after server death")
			}
		}
		c.Close()
		pc.Close()
		start := time.Now()
		if _, e = o.DialTCP(ctxTimeout(t, 3*time.Second), echo); e == nil {
			t.Fatal("dial succeeded while server down")
		} else {
			t.Logf("dial while down failed after %v: %v", time.Since(start).Round(time.Millisecond), e)
		}
		sb.start(t)
		c, e = o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal("dial after restart:", e)
		}
		if e = echoRoundTrip(c, []byte("after restart")); e != nil {
			t.Fatal(e)
		}
		c.Close()
		if n := o.sessionsCreated.Load(); n != 3 {
			t.Fatalf("sessions created %d, want 3 (TCP + UoT before kill, 1 new after restart)", n)
		}
		t.Logf("recovered: sessions created=%d under dials=%d", o.sessionsCreated.Load(), under.n.Load())
	})
}
