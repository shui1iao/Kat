package anytls_test

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	at "github.com/shui1iao/Kat/internal/outbound/anytls"
)

// Interop with Kat's own AnyTLS inbound through the real kernel (kernel.Start,
// loopback). Gated by KAT_INTEROP_KERNEL=1; run under the shared flock.

func startKernel(t *testing.T, listen, certFile, keyFile, password string) (*kernel.Server, outbound.Addr) {
	t.Helper()
	cfg := kernel.Config{Inbounds: []kernel.Inbound{{
		Protocol: "anytls", Listen: listen,
		TLS:    &kernel.TLSConfig{Cert: certFile, Key: keyFile},
		AnyTLS: &kernel.AnyTLSOptions{Password: password},
	}}}
	s, e := kernel.Start(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ta := s.Addresses()[0].(*net.TCPAddr)
	return s, outbound.Addr{Host: ta.IP.String(), Port: uint16(ta.Port)}
}

func closeKernel(s *kernel.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.Close(ctx)
}

func TestKatKernelInterop(t *testing.T) {
	if os.Getenv("KAT_INTEROP_KERNEL") == "" {
		t.Skip("set KAT_INTEROP_KERNEL=1 to run Kat kernel interop")
	}
	certFile, keyFile, pin := at.ExportCertFiles(t)
	const password = "kat-kernel-interop"
	srv, addr := startKernel(t, "127.0.0.1:0", certFile, keyFile, password)
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			closeKernel(srv)
		}
	})
	echo := at.ExportTCPEcho(t)
	under := at.ExportNewCounting()
	ob, e := at.New(at.ExportBaseOptions(addr, password, &outbound.TLSOptions{PinSHA256: pin}), under)
	if e != nil {
		t.Fatal(e)
	}
	defer ob.Close()

	c, e := ob.DialTCP(at.ExportCtx(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = at.ExportEchoRT(c, []byte("hello kat kernel")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	at.ExportWaitIdle(t, ob, 1)
	at.ExportConcurrentEcho(t, ob, echo, 8, 200<<10) // 8 distinct sessions, one reused
	if n, d := at.ExportSessionsCreated(ob), at.ExportCountedDials(under); n != 8 || d != 8 {
		t.Fatalf("sessions=%d under dials=%d, want 8/8", n, d)
	}
	at.ExportWaitIdle(t, ob, 4)
	c, e = ob.DialTCP(at.ExportCtx(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = at.ExportEchoRT(c, []byte("reuse")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if n, d := at.ExportSessionsCreated(ob), at.ExportCountedDials(under); n != 8 || d != 8 {
		t.Fatalf("reuse: sessions=%d under dials=%d, want 8/8", n, d)
	}
	t.Logf("TCP via Kat kernel: echo + 8 concurrent on 8 sessions + idle reuse (under dials 8)")

	pc, e := ob.ListenPacket(at.ExportCtx(t, 5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	u1, u2 := at.ExportUDPEcho(t, "k1:"), at.ExportUDPEcho(t, "k2:")
	at.ExportUDPRT(t, pc, u1, []byte("kernel uot 1"), "k1:")
	at.ExportUDPRT(t, pc, u2, []byte("kernel uot 2"), "k2:")
	at.ExportUDPRT(t, pc, u1, at.ExportPattern(7, 1400), "k1:")
	if d := at.ExportCountedDials(under); d != 8 {
		t.Fatalf("UoT should take an idle session; under dials=%d", d)
	}
	t.Logf("UoT v2 via Kat kernel: replies from %v and %v verified", u1, u2)

	// Server shutdown with live streams: they error; a restarted server gets a new session.
	c, e = ob.DialTCP(at.ExportCtx(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	closeKernel(srv)
	stopped = true
	errc := make(chan error, 2)
	go func() { _, e := c.Read(make([]byte, 8)); errc <- e }()
	go func() { _, _, e := pc.ReadFrom(make([]byte, 8)); errc <- e }()
	for i := 0; i < 2; i++ {
		select {
		case e := <-errc:
			if e == nil {
				t.Fatal("read succeeded after server shutdown")
			}
			t.Logf("live stream after kernel shutdown: %v", e)
		case <-time.After(5 * time.Second):
			t.Fatal("stream hangs after server shutdown")
		}
	}
	c.Close()
	pc.Close()
	before := at.ExportSessionsCreated(ob)
	srv2, _ := startKernel(t, net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port))), certFile, keyFile, password)
	defer closeKernel(srv2)
	c, e = ob.DialTCP(at.ExportCtx(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal("dial after restart:", e)
	}
	if e = at.ExportEchoRT(c, []byte("after restart")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if n := at.ExportSessionsCreated(ob); n != before+1 {
		t.Fatalf("sessions=%d, want %d (one new session after restart)", n, before+1)
	}
}
