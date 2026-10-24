package anytls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/outbound"
)

const testPassword = "kat-outbound-test-password"

func TestValidate(t *testing.T) {
	cert := newTestCert(t)
	ok := outbound.Options{Name: "a", Type: "anytls", Server: "example.com", Port: 443, Password: "s3cret-pw", TLS: &outbound.TLSOptions{}}
	yes, no := true, false
	cases := []struct {
		name string
		mut  func(o *outbound.Options)
		good bool
	}{
		{"minimal", func(o *outbound.Options) {}, true},
		{"ip server", func(o *outbound.Options) { o.Server = "2001:db8::1" }, true},
		{"udp off", func(o *outbound.Options) { o.UDP = &no }, true},
		{"udp on", func(o *outbound.Options) { o.UDP = &yes }, true},
		{"via", func(o *outbound.Options) { o.Via = "hk" }, true},
		{"idle bounds", func(o *outbound.Options) { o.IdleSessions = 32; o.IdleTimeout = outbound.Duration(10 * time.Minute) }, true},
		{"idle low", func(o *outbound.Options) { o.IdleSessions = 1; o.IdleTimeout = outbound.Duration(time.Second) }, true},
		{"ca", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{CA: cert.certFile} }, true},
		{"pin", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{PinSHA256: cert.pin} }, true},
		{"insecure", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{Insecure: true} }, true},
		{"server_name domain", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "sni.example.com"} }, true},
		{"server_name trailing dot", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "sni.example.com."} }, true},
		{"server_name ip", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "192.0.2.1"} }, true},
		{"server_name with pin", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "localhost", PinSHA256: cert.pin} }, true},
		{"wrong type", func(o *outbound.Options) { o.Type = "trojan" }, false},
		{"no name", func(o *outbound.Options) { o.Name = "" }, false},
		{"no server", func(o *outbound.Options) { o.Server = "" }, false},
		{"bad server", func(o *outbound.Options) { o.Server = "exa mple.com" }, false},
		{"zone server", func(o *outbound.Options) { o.Server = "fe80::1%eth0" }, false},
		{"bracket server", func(o *outbound.Options) { o.Server = "[::1]" }, false},
		{"no port", func(o *outbound.Options) { o.Port = 0 }, false},
		{"no password", func(o *outbound.Options) { o.Password = "" }, false},
		{"long password", func(o *outbound.Options) { o.Password = strings.Repeat("x", 4097) }, false},
		{"username", func(o *outbound.Options) { o.Username = "u" }, false},
		{"method", func(o *outbound.Options) { o.Method = "aes-128-gcm" }, false},
		{"key", func(o *outbound.Options) { o.Key = "AAAA" }, false},
		{"no tls", func(o *outbound.Options) { o.TLS = nil }, false},
		{"idle sessions high", func(o *outbound.Options) { o.IdleSessions = 33 }, false},
		{"idle sessions negative", func(o *outbound.Options) { o.IdleSessions = -1 }, false},
		{"idle timeout low", func(o *outbound.Options) { o.IdleTimeout = outbound.Duration(999 * time.Millisecond) }, false},
		{"idle timeout high", func(o *outbound.Options) { o.IdleTimeout = outbound.Duration(10*time.Minute + time.Second) }, false},
		{"idle timeout negative", func(o *outbound.Options) { o.IdleTimeout = outbound.Duration(-time.Second) }, false},
		{"pin+insecure", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{PinSHA256: cert.pin, Insecure: true} }, false},
		{"ca+insecure", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{CA: cert.certFile, Insecure: true} }, false},
		{"bad pin", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{PinSHA256: "abcd"} }, false},
		{"missing ca", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{CA: "/nonexistent/ca.pem"} }, false},
		{"server_name space", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "bad name"} }, false},
		{"server_name zone", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "fe80::1%eth0"} }, false},
		{"server_name bracket", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "[::1]"} }, false},
		{"server_name empty label", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "a..b"} }, false},
		{"server_name leading hyphen", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "-a.example.com"} }, false},
		{"server_name long label", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: strings.Repeat("a", 64) + ".com"} }, false},
		{"server_name only dot", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "."} }, false},
		{"server_name with port", func(o *outbound.Options) { o.TLS = &outbound.TLSOptions{ServerName: "example.com:443"} }, false},
	}
	for _, c := range cases {
		o := ok
		c.mut(&o)
		e := Validate(o)
		if (e == nil) != c.good {
			t.Errorf("%s: Validate=%v want ok=%v", c.name, e, c.good)
		}
		if e != nil && strings.Contains(e.Error(), o.Password) && o.Password != "" {
			t.Errorf("%s: error leaks password", c.name)
		}
	}
	if _, e := New(ok, nil); e == nil {
		t.Error("New accepted nil under")
	}
}

type failDialer struct{ t *testing.T }

func (d failDialer) DialTCP(context.Context, outbound.Addr) (net.Conn, error) {
	d.t.Error("network I/O during New")
	return nil, errors.New("no")
}
func (d failDialer) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (d failDialer) UDP() bool { return false }

func TestNewNoIOAndCapabilities(t *testing.T) {
	no := false
	o := outbound.Options{Name: "n", Type: "anytls", Server: "203.0.113.9", Port: 443, Password: "p", TLS: &outbound.TLSOptions{}}
	ob := newTestOutbound(t, o, failDialer{t})
	if ob.Name() != "n" || ob.Type() != "anytls" || !ob.UDP() {
		t.Fatal("name/type/udp")
	}
	if ob.idleMax != 4 || ob.idleTimeout != 30*time.Second {
		t.Fatal("defaults", ob.idleMax, ob.idleTimeout)
	}
	o.UDP = &no
	ob2 := newTestOutbound(t, o, failDialer{t})
	if ob2.UDP() {
		t.Fatal("udp:false ignored")
	}
	if _, e := ob2.ListenPacket(context.Background()); !errors.Is(e, outbound.ErrUDPUnsupported) {
		t.Fatal("ListenPacket with udp disabled:", e)
	}
}

func TestPaddingScheme(t *testing.T) {
	p, e := parsePaddingScheme(A.DefaultPaddingScheme)
	if e != nil {
		t.Fatal(e)
	}
	if p.stop != 8 || p.authPadding() != 30 {
		t.Fatal("default scheme", p.stop, p.authPadding())
	}
	// md5 matches the value Kat's server and the public fixtures use.
	if p.md5 != "75cff2ad89aadf5e257059ee571ebe11" {
		t.Fatal("md5", p.md5)
	}
	for i := 0; i < 50; i++ {
		s := p.sizes(2)
		if len(s) != 9 || s[0] < 400 || s[0] > 500 || s[1] != checkMark {
			t.Fatal("sizes(2)", s)
		}
	}
	if p.sizes(8) != nil {
		t.Fatal("no padding at stop")
	}
	for _, bad := range []string{"", "0=1-2", "stop=x", "stop=2\n0=a-b", "stop=2\nstop=3", "stop=2\n1=1-2\n1=3-4", "stop=2\n1=70000-70001"} {
		if _, e := parsePaddingScheme(bad); e == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Record splitting: frames must reassemble exactly; padding only appends waste frames.
func TestWritePaddedFraming(t *testing.T) {
	p, _ := parsePaddingScheme("stop=4\n0=30-30\n1=100-100\n2=20-20,c,50-50\n3=10-10,30-30")
	client, server := net.Pipe()
	defer client.Close()
	s := &session{conn: client, scheme: p, packet: 1}
	payloads := [][]byte{appendFrame(nil, cmdPSH, 1, []byte("abc")), appendFrame(nil, cmdPSH, 1, pattern(1, 45)), appendFrame(nil, cmdPSH, 1, pattern(2, 5)), appendFrame(nil, cmdPSH, 1, pattern(3, 300))}
	got := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(server); got <- b }()
	for _, w := range payloads {
		if e := s.writePadded(w); e != nil {
			t.Fatal(e)
		}
	}
	client.Close()
	wire := <-got
	var data []byte
	waste := 0
	for len(wire) > 0 {
		n := int(binary.BigEndian.Uint16(wire[5:7]))
		switch wire[0] {
		case cmdPSH:
			data = append(data, wire[7:7+n]...)
		case cmdWaste:
			waste++
		default:
			t.Fatal("cmd", wire[0])
		}
		wire = wire[7+n:]
	}
	want := append(append(append([]byte("abc"), pattern(1, 45)...), pattern(2, 5)...), pattern(3, 300)...)
	if string(data) != string(want) {
		t.Fatal("payload corrupted by padding")
	}
	if waste == 0 {
		t.Fatal("no waste frames emitted")
	}
}

func katFixture(t *testing.T, cfg A.Config) (testCert, *katServer) {
	cert := newTestCert(t)
	if cfg.Password == "" {
		cfg.Password = testPassword
	}
	return cert, startKatServer(t, cert, cfg)
}

// Kat's own server, in process: TCP echo; 8 concurrent streams on 8 distinct
// sessions; idle reuse after close (no new under dial); UoT on an exclusive
// session to two targets, whose session returns to the pool afterwards.
func TestKatServerTCPConcurrentReuseUDP(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	under := &countingDialer{}
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), under)

	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c, []byte("hello anytls")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	waitIdle(t, o, 1)
	concurrentEcho(t, o, echo, 8, 200<<10) // one of them reuses the idle session
	if n, d := o.sessionsCreated.Load(), under.n.Load(); n != 8 || d != 8 {
		t.Fatalf("sessions=%d under dials=%d, want 8/8", n, d)
	}
	waitIdle(t, o, 4) // idle_sessions default 4 bounds the pool
	idleBefore := idleSet(o)
	c2, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if !idleBefore[c2.(*stream).s] {
		t.Fatal("new stream did not take an idle session")
	}
	if busy, idle := o.sessionCount(); busy != 1 || idle != 3 {
		t.Fatalf("taken session must leave the idle pool: busy=%d idle=%d", busy, idle)
	}
	if e = echoRoundTrip(c2, []byte("reused")); e != nil {
		t.Fatal(e)
	}
	c2.Close()
	if n, d, a := o.sessionsCreated.Load(), under.n.Load(), ks.accepted.Load(); n != 8 || d != 8 || a != 8 {
		t.Fatalf("reuse: sessions=%d under dials=%d server accepts=%d, want 8/8/8", n, d, a)
	}
	t.Logf("tcp: echo + 8 concurrent on 8 sessions + idle reuse; sessions=%d under dials=%d", o.sessionsCreated.Load(), under.n.Load())

	pc, e := o.ListenPacket(ctxTimeout(t, 5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	uotSession := pc.(*packetConn).st.s
	u1, u2 := udpEchoServer(t, "one:"), udpEchoServer(t, "two:")
	udpRoundTrip(t, pc, u1, []byte("datagram-1"), "one:")
	udpRoundTrip(t, pc, u2, []byte("datagram-2"), "two:")
	udpRoundTrip(t, pc, u1, pattern(9, 1400), "one:")
	// Domain source addresses round-trip through the UoT address encoding.
	udpRoundTrip(t, pc, outbound.Addr{Host: "echo.test", Port: 5353}, []byte("domain"), "")
	if busy, _ := o.sessionCount(); busy != 1 {
		t.Fatal("UoT must own one session exclusively", busy)
	}
	pc.Close()
	waitIdle(t, o, 4)
	c3, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if c3.(*stream).s != uotSession {
		t.Fatal("UoT session did not return to the pool as most recently used")
	}
	if e = echoRoundTrip(c3, []byte("after uot")); e != nil {
		t.Fatal(e)
	}
	c3.Close()
	if d := under.n.Load(); d != 8 {
		t.Fatalf("UoT and later TCP should reuse idle sessions; under dials=%d", d)
	}
}

func idleSet(o *Outbound) map[*session]bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := map[*session]bool{}
	for _, s := range o.sessions {
		if s.reserved == 0 {
			m[s] = true
		}
	}
	return m
}

func waitIdle(t *testing.T, o *Outbound, want int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if busy, idle := o.sessionCount(); busy == 0 && idle == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	busy, idle := o.sessionCount()
	t.Fatalf("sessions busy=%d idle=%d, want 0/%d", busy, idle, want)
}

func TestTLSModesAgainstSelfSigned(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	for _, m := range []struct {
		name string
		opt  *outbound.TLSOptions
		ok   bool
	}{
		{"default", &outbound.TLSOptions{}, false},
		{"ca", &outbound.TLSOptions{CA: cert.certFile}, true},
		{"pin", &outbound.TLSOptions{PinSHA256: cert.pin}, true},
		{"insecure", &outbound.TLSOptions{Insecure: true}, true},
		{"wrong pin", &outbound.TLSOptions{PinSHA256: strings.Repeat("ab", 32)}, false},
	} {
		o := newTestOutbound(t, baseOptions(ks.addr, testPassword, m.opt), &countingDialer{})
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if m.ok {
			if e != nil {
				t.Fatalf("%s: %v", m.name, e)
			}
			if e = echoRoundTrip(c, []byte(m.name)); e != nil {
				t.Fatalf("%s: %v", m.name, e)
			}
			c.Close()
		} else if e == nil {
			t.Fatalf("%s: accepted", m.name)
		} else {
			t.Logf("%s rejected: %v", m.name, e)
		}
	}
}

func TestWrongPasswordFailsFast(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	o := newTestOutbound(t, baseOptions(ks.addr, "wrong-password", &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	start := time.Now()
	_, e := o.DialTCP(ctxTimeout(t, 5*time.Second), tcpEchoServer(t))
	if e == nil {
		t.Fatal("wrong password accepted")
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("wrong password took %v", el)
	}
	if strings.Contains(e.Error(), "wrong-password") || strings.Contains(e.Error(), testPassword) {
		t.Fatal("error leaks password")
	}
	t.Logf("wrong password rejected in %v: %v", time.Since(start).Round(time.Millisecond), e)
	if _, e = o.ListenPacket(ctxTimeout(t, 5*time.Second)); e == nil {
		t.Fatal("UoT with wrong password accepted")
	}
}

// Session killed under live streams: they error promptly; the next dial builds
// a new session.
func TestSessionFailureRecovery(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	under := &countingDialer{}
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), under)
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c, []byte("before")); e != nil {
		t.Fatal(e)
	}
	pc, e := o.ListenPacket(ctxTimeout(t, 5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if pc.(*packetConn).st.s == c.(*stream).s {
		t.Fatal("UoT shares the busy TCP session")
	}
	under.closeAll()
	errc := make(chan error, 2)
	go func() { _, e := c.Read(make([]byte, 10)); errc <- e }()
	go func() { _, _, e := pc.ReadFrom(make([]byte, 10)); errc <- e }()
	for i := 0; i < 2; i++ {
		select {
		case e := <-errc:
			if e == nil {
				t.Fatal("read succeeded on dead session")
			}
			t.Logf("live stream error: %v", e)
		case <-time.After(3 * time.Second):
			t.Fatal("stream hangs after session failure")
		}
	}
	if _, e = c.Write([]byte("x")); e == nil {
		t.Fatal("write succeeded on dead session")
	}
	c.Close()
	pc.Close()
	c2, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c2, []byte("after")); e != nil {
		t.Fatal(e)
	}
	c2.Close()
	if n := o.sessionsCreated.Load(); n != 3 {
		t.Fatalf("sessions created %d, want 3 (2 dead + 1 new)", n)
	}
}

func TestSYNACKRefusal(t *testing.T) {
	// Server-wide limit of one stream: the second (on its own session) is refused.
	cert, ks := katFixture(t, A.Config{MaxTotalStreams: 1})
	echo := tcpEchoServer(t)
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	_, e = o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e == nil || !strings.Contains(e.Error(), "refused") {
		t.Fatalf("second stream beyond server limit: %v", e)
	}
	t.Logf("SYNACK refusal surfaced: %v", e)
	if e = echoRoundTrip(c, []byte("first still fine")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	// The refused stream's session stays healthy and is pooled for reuse.
	for i := 0; ; i++ {
		c, e = o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e == nil {
			break
		}
		if i > 50 { // server frees its stream slot asynchronously after FIN
			t.Fatal(e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e = echoRoundTrip(c, []byte("after refusal")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if n := o.sessionsCreated.Load(); n != 2 {
		t.Fatalf("sessions created %d, want 2", n)
	}
}

// A reader that stops reading only stalls its own session; buffered memory is
// bounded and nothing is lost once it reads again.
func TestSlowReaderBoundedAndIsolated(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	const total = 8 << 20
	ln, e := net.Listen("tcp", "127.0.0.1:0")
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
		_, _ = c.Write(pattern(11, total))
	}()
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	slow, e := o.DialTCP(ctxTimeout(t, 5*time.Second), mustAddr(t, ln.Addr().String()))
	if e != nil {
		t.Fatal(e)
	}
	defer slow.Close()
	time.Sleep(time.Second) // server pushes; the client does not read
	st := slow.(*stream)
	st.mu.Lock()
	buffered := st.inBytes
	st.mu.Unlock()
	if buffered > maxStreamBuffer+maxFrame {
		t.Fatalf("unread buffer unbounded: %d", buffered)
	}
	start := time.Now()
	fast, e := o.DialTCP(ctxTimeout(t, 5*time.Second), tcpEchoServer(t))
	if e != nil {
		t.Fatal(e)
	}
	if fast.(*stream).s == st.s {
		t.Fatal("second stream joined the stalled session")
	}
	if e = echoRoundTrip(fast, pattern(12, 1<<20)); e != nil {
		t.Fatal(e)
	}
	fast.Close()
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("other stream delayed by the stalled reader: %v", el)
	}
	slow.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, total)
	if _, e = io.ReadFull(slow, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != string(pattern(11, total)) {
		t.Fatal("slow stream data corrupted")
	}
	t.Logf("stalled reader buffered %d bytes (cap %d); sibling echo of 1MiB took %v", buffered, maxStreamBuffer, time.Since(start).Round(time.Millisecond))
}

// Deadlines act on the stream, never on the physical connection: the session
// survives a timeout and the stream is usable after refreshing the deadline.
func TestDeadlinesAreStreamScoped(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	c1, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	defer c1.Close()
	c2, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	c1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, e = c1.Read(make([]byte, 1))
	var ne net.Error
	if !errors.As(e, &ne) || !ne.Timeout() || !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %v", e)
	}
	if e = echoRoundTrip(c2, []byte("sibling")); e != nil {
		t.Fatal(e)
	}
	c1.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, e = c1.Write([]byte("x")); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline: %v", e)
	}
	if e = echoRoundTrip(c1, []byte("refreshed")); e != nil {
		t.Fatal(e)
	}
	if c1.(*stream).s.failed.Load() {
		t.Fatal("deadline broke the session")
	}
	if n := o.sessionsCreated.Load(); n != 2 {
		t.Fatalf("sessions %d", n)
	}
}

func TestHeartbeatAndPaddingUpdate(t *testing.T) {
	custom := "stop=3\n0=10-20\n1=50-60\n2=100-120"
	cert, ks := katFixture(t, A.Config{PaddingScheme: custom})
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), outbound.Addr{Host: "ping.test", Port: 1})
	if e != nil {
		t.Fatal(e)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 4)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "pong" {
		t.Fatalf("server heartbeat not answered: %q %v", b, e)
	}
	if o.paddingUpdates.Load() != 1 || o.scheme.Load().raw != custom {
		t.Fatal("padding scheme update not applied")
	}
	// A second session (the first is busy with its stream) announces the
	// updated md5, so the server sends no further update.
	c2, e := o.DialTCP(ctxTimeout(t, 5*time.Second), tcpEchoServer(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c2, []byte("new scheme")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	c2.Close()
	if o.sessionsCreated.Load() != 2 || o.paddingUpdates.Load() != 1 {
		t.Fatalf("sessions=%d updates=%d", o.sessionsCreated.Load(), o.paddingUpdates.Load())
	}
}

// Raw protocol server: waste frames, server settings, SYNACK, data, then alert.
func TestAlertAndWasteFrames(t *testing.T) {
	cert := newTestCert(t)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		raw, e := ln.Accept()
		if e != nil {
			return
		}
		c := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert.pair}})
		defer c.Close()
		head := make([]byte, 34)
		if _, e = io.ReadFull(c, head); e != nil {
			return
		}
		io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(head[32:])))
		var id uint32
		for id == 0 { // read until the first PSH (target address)
			h := make([]byte, 7)
			if _, e = io.ReadFull(c, h); e != nil {
				return
			}
			io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(h[5:])))
			if h[0] == cmdPSH {
				id = binary.BigEndian.Uint32(h[1:5])
			}
		}
		var w []byte
		w = appendFrame(w, cmdWaste, 0, make([]byte, 33))
		w = appendFrame(w, cmdServerSettings, 0, []byte("v=2"))
		w = appendFrame(w, cmdWaste, 0, nil)
		w = appendFrame(w, cmdSYNACK, id, nil)
		w = appendFrame(w, cmdPSH, id, []byte("hi"))
		w = appendFrame(w, cmdAlert, 0, []byte("test alert\x00"))
		c.Write(w)
		time.Sleep(time.Second)
	}()
	o := newTestOutbound(t, baseOptions(mustAddr(t, ln.Addr().String()), testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), outbound.Addr{Host: "example.com", Port: 80})
	if e != nil {
		t.Fatal(e)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 2)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "hi" {
		t.Fatal(string(b), e)
	}
	_, e = c.Read(b)
	if e == nil || !strings.Contains(e.Error(), "server alert: test alert?") {
		t.Fatalf("alert: %v", e)
	}
	t.Logf("alert surfaced: %v", e)
}

// Idle sessions expire after idle_timeout; the pool is bounded by idle_sessions;
// Close ends every background goroutine.
func TestIdleExpiryBoundAndCloseNoLeak(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	base := runtime.NumGoroutine()
	opt := baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin})
	opt.IdleTimeout = outbound.Duration(time.Second)
	opt.IdleSessions = 2
	ob, e := New(opt, &countingDialer{})
	if e != nil {
		t.Fatal(e)
	}
	o := ob.(*Outbound)
	var conns []net.Conn
	for i := 0; i < 4; i++ {
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		if e = echoRoundTrip(c, []byte("x")); e != nil {
			t.Fatal(e)
		}
		conns = append(conns, c)
	}
	if busy, idle := o.sessionCount(); busy != 4 || idle != 0 {
		t.Fatal("one session per active stream: busy", busy, "idle", idle)
	}
	for _, c := range conns {
		c.Close()
	}
	if _, idle := o.sessionCount(); idle != 2 {
		t.Fatalf("idle pool not bounded: %d", idle)
	}
	// Most recently used idle session is reused first.
	o.mu.Lock()
	var newest *session
	for _, s := range o.sessions {
		if newest == nil || s.lastUsed.After(newest.lastUsed) {
			newest = s
		}
	}
	o.mu.Unlock()
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if c.(*stream).s != newest {
		t.Fatal("did not reuse the most recently used idle session")
	}
	c.Close()
	time.Sleep(1500 * time.Millisecond)
	if busy, idle := o.sessionCount(); busy+idle != 0 {
		t.Fatalf("idle sessions not expired: busy=%d idle=%d", busy, idle)
	}
	waitGoroutines(t, base)

	// Close with idle sessions present.
	for i := 0; i < 2; i++ {
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		conns[i] = c
	}
	conns[0].Close()
	o.Close()
	if _, e = o.DialTCP(ctxTimeout(t, time.Second), echo); !errors.Is(e, net.ErrClosed) {
		t.Fatal("dial after Close:", e)
	}
	if e = echoRoundTrip(conns[1], []byte("in-flight survives Close")); e != nil {
		t.Fatal(e)
	}
	conns[1].Close()
	waitGoroutines(t, base)
	if n := o.sessionsCreated.Load(); n != 6 {
		t.Logf("sessions created %d", n)
	}
}

// Chain: the outer outbound reaches its server through an inner anytls
// outbound (TCP and UoT); only the counting stub touches the network.
func TestChainThroughUnder(t *testing.T) {
	cert1, ks1 := katFixture(t, A.Config{})
	cert2, ks2 := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	stub := &countingDialer{}
	inner := newTestOutbound(t, baseOptions(ks1.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert1.pin}), stub)
	outer := newTestOutbound(t, baseOptions(ks2.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert2.pin}), inner)
	c, e := outer.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c, pattern(5, 100<<10)); e != nil {
		t.Fatal(e)
	}
	pc, e := outer.ListenPacket(ctxTimeout(t, 5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	udpRoundTrip(t, pc, udpEchoServer(t, "chain:"), []byte("uot over chain"), "chain:")
	// Two concurrent outer sessions, each carried by its own inner session.
	if stub.n.Load() != 2 || ks1.accepted.Load() != 2 || ks2.accepted.Load() != 2 {
		t.Fatalf("stub dials=%d server1 accepts=%d server2 accepts=%d, want 2/2/2", stub.n.Load(), ks1.accepted.Load(), ks2.accepted.Load())
	}
	pc.Close()
	c.Close()
	waitIdle(t, outer, 2)
	c, e = outer.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c, []byte("reused through chain")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if stub.n.Load() != 2 || ks2.accepted.Load() != 2 {
		t.Fatal("idle outer session not reused through the chain")
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, sc := range stub.conns {
		if dst := sc.RemoteAddr().String(); dst != ks1.addr.String() {
			t.Fatal("stub dialed", dst)
		}
	}
}

// Every server connection goes through under.DialTCP.
func TestAllServerConnectionsUseUnder(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	stub := &countingDialer{}
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), stub)
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		conns = append(conns, c)
	}
	pc, e := o.ListenPacket(ctxTimeout(t, 5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	udpRoundTrip(t, pc, udpEchoServer(t, ""), []byte("u"), "")
	if d, a, s := stub.n.Load(), ks.accepted.Load(), o.sessionsCreated.Load(); d != 4 || a != 4 || s != 4 {
		t.Fatalf("under dials=%d server accepts=%d sessions=%d, want 4/4/4", d, a, s)
	}
	pc.Close()
	for _, c := range conns {
		c.Close()
	}
}

// Pooled sessions that died while idle (server restart) are skipped: the next
// dial still succeeds, on a fresh session.
func TestDeadIdleSessionsSkipped(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	echo := tcpEchoServer(t)
	under := &countingDialer{}
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), under)
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.Close()
	}
	waitIdle(t, o, 3)
	under.closeAll()
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal("dial after idle sessions died:", e)
	}
	if e = echoRoundTrip(c, []byte("fresh")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if n := o.sessionsCreated.Load(); n != 4 {
		t.Fatalf("sessions created %d, want 4", n)
	}
}
