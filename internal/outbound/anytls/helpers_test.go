package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/outbound"
)

// testCert is a self-signed loopback certificate written into the test's temp dir.
type testCert struct {
	certFile, keyFile string
	pin               string
	pair              tls.Certificate
}

func newTestCert(t *testing.T) testCert {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "kat-anytls-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"},
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	c := testCert{certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem")}
	if e = os.WriteFile(c.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(der)
	c.pin = hex.EncodeToString(sum[:])
	c.pair, e = tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

// countingDialer is the "under" hop: plain loopback TCP, counted and recorded.
type countingDialer struct {
	n     atomic.Int64
	mu    sync.Mutex
	conns []net.Conn
}

func (d *countingDialer) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	d.n.Add(1)
	var nd net.Dialer
	c, e := nd.DialContext(ctx, "tcp", dst.String())
	if e == nil {
		d.mu.Lock()
		d.conns = append(d.conns, c)
		d.mu.Unlock()
	}
	return c, e
}
func (d *countingDialer) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (d *countingDialer) UDP() bool { return false }

func (d *countingDialer) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
}

func mustAddr(t *testing.T, s string) outbound.Addr {
	t.Helper()
	ap, e := net.ResolveTCPAddr("tcp", s)
	if e != nil {
		t.Fatal(e)
	}
	host := ap.IP.String()
	return outbound.Addr{Host: host, Port: uint16(ap.Port)}
}

func tcpEchoServer(t *testing.T) outbound.Addr {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return mustAddr(t, ln.Addr().String())
}

// udpEchoServer answers each datagram with prefix+payload from its own address.
func udpEchoServer(t *testing.T, prefix string) outbound.Addr {
	t.Helper()
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(prefix), buf[:n]...), from)
		}
	}()
	ua := pc.LocalAddr().(*net.UDPAddr)
	return outbound.Addr{Host: ua.IP.String(), Port: uint16(ua.Port)}
}

// katServer runs Kat's own AnyTLS server codec in process behind a TLS listener.
// TCP streams are relayed to their real targets; UoT datagrams are relayed to
// real UDP targets, except "echo.test" which is answered in place.
type katServer struct {
	addr     outbound.Addr
	ln       net.Listener
	accepted atomic.Int64
	wg       sync.WaitGroup
}

func startKatServer(t *testing.T, cert testCert, cfg A.Config) *katServer {
	t.Helper()
	srv, e := A.NewServer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ks := &katServer{addr: mustAddr(t, ln.Addr().String()), ln: ln}
	ctx, cancel := context.WithCancel(context.Background())
	tc := &tls.Config{Certificates: []tls.Certificate{cert.pair}, MinVersion: tls.VersionTLS12}
	ks.wg.Add(1)
	go func() {
		defer ks.wg.Done()
		for {
			raw, e := ln.Accept()
			if e != nil {
				return
			}
			ks.accepted.Add(1)
			ks.wg.Add(1)
			go func() {
				defer ks.wg.Done()
				c := tls.Server(raw, tc)
				hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
				e := c.HandshakeContext(hctx)
				hcancel()
				if e != nil {
					raw.Close()
					return
				}
				_ = srv.Serve(ctx, c, katHandler)
			}()
		}
	}()
	t.Cleanup(func() { cancel(); ln.Close(); ks.wg.Wait() })
	return ks
}

func katHandler(ctx context.Context, st *A.Stream, req A.Request) {
	if req.UDP != nil {
		katUDP(ctx, req.UDP)
		return
	}
	if req.Target.Host == "ping.test" {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		e := st.Ping(pctx)
		cancel()
		if e == nil {
			_, _ = st.Write([]byte("pong"))
		} else {
			_, _ = st.Write([]byte("fail"))
		}
		buf := make([]byte, 16)
		_, _ = st.Read(buf)
		return
	}
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	target, e := d.DialContext(dctx, "tcp", req.Target.String())
	cancel()
	if e != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(target, st); target.Close(); close(done) }()
	_, _ = io.Copy(st, target)
	st.Close()
	target.Close()
	<-done
}

func katUDP(ctx context.Context, d *A.DatagramConn) {
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		return
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			ua := from.(*net.UDPAddr)
			if d.WritePacket(A.Address{Host: ua.IP.String(), Port: uint16(ua.Port)}, append([]byte(nil), buf[:n]...)) != nil {
				return
			}
		}
	}()
	for {
		to, payload, e := d.ReadPacket()
		if e != nil {
			return
		}
		if to.Host == "echo.test" {
			if d.WritePacket(to, payload) != nil {
				return
			}
			continue
		}
		ua, e := net.ResolveUDPAddr("udp", to.String())
		if e != nil {
			continue
		}
		_, _ = pc.WriteTo(payload, ua)
	}
}

func baseOptions(server outbound.Addr, password string, tlsOpt *outbound.TLSOptions) outbound.Options {
	return outbound.Options{Name: "at", Type: "anytls", Server: server.Host, Port: server.Port, Password: password, TLS: tlsOpt}
}

func newTestOutbound(t *testing.T, o outbound.Options, under outbound.Dialer) *Outbound {
	t.Helper()
	ob, e := New(o, under)
	if e != nil {
		t.Fatal(e)
	}
	a := ob.(*Outbound)
	t.Cleanup(func() { a.Close() })
	return a
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func echoRoundTrip(c net.Conn, payload []byte) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	errc := make(chan error, 1)
	go func() { _, e := c.Write(payload); errc <- e }()
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil {
		return fmt.Errorf("read: %w", e)
	}
	if e := <-errc; e != nil {
		return fmt.Errorf("write: %w", e)
	}
	if !bytes.Equal(got, payload) {
		return errors.New("echo mismatch")
	}
	return nil
}

func pattern(seed, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(seed*31 + i*7)
	}
	return b
}

// concurrentEcho opens k streams at once (no other streams open), each echoing
// distinct data. Every active stream must own a distinct session.
func concurrentEcho(t *testing.T, o *Outbound, dst outbound.Addr, k, size int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, k)
	conns := make(chan net.Conn, k)
	start := make(chan struct{})
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := o.DialTCP(ctxTimeout(t, 10*time.Second), dst)
			if e != nil {
				errs <- e
				return
			}
			conns <- c
			<-start
			if e := echoRoundTrip(c, pattern(i, size)); e != nil {
				errs <- fmt.Errorf("stream %d: %w", i, e)
			}
		}(i)
	}
	// All k streams are open simultaneously before any data flows.
	deadline := time.After(10 * time.Second)
	opened := make([]net.Conn, 0, k)
	for len(opened) < k {
		select {
		case c := <-conns:
			opened = append(opened, c)
		case e := <-errs:
			t.Fatal(e)
		case <-deadline:
			t.Fatal("timeout opening streams")
		}
	}
	distinct := map[*session]bool{}
	for _, c := range opened {
		distinct[c.(*stream).s] = true
	}
	if busy, idle := o.sessionCount(); len(distinct) != k || busy != k || idle != 0 {
		t.Fatalf("%d concurrent streams: distinct sessions=%d busy=%d idle=%d, want %d/%d/0", k, len(distinct), busy, idle, k, k)
	}
	t.Logf("%d concurrent streams on %d distinct sessions", k, len(distinct))
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	for _, c := range opened {
		c.Close()
	}
}

func udpRoundTrip(t *testing.T, pc outbound.PacketConn, dst outbound.Addr, payload []byte, prefix string) {
	t.Helper()
	if _, e := pc.WriteTo(payload, dst); e != nil {
		t.Fatal(e)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 70000)
	n, src, e := pc.ReadFrom(buf)
	if e != nil {
		t.Fatal(e)
	}
	if src != dst {
		t.Fatalf("source %v, want %v", src, dst)
	}
	if want := append([]byte(prefix), payload...); !bytes.Equal(buf[:n], want) {
		t.Fatalf("udp payload mismatch from %v: got %q", dst, buf[:min(n, 32)])
	}
}

// waitGoroutines polls until the goroutine count is back to at most base.
func waitGoroutines(t *testing.T, base int) {
	t.Helper()
	var n int
	for i := 0; i < 100; i++ {
		n = runtime.NumGoroutine()
		if n <= base {
			t.Logf("goroutines back to %d (baseline %d)", n, base)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	t.Fatalf("goroutine leak: %d > baseline %d\n%s", n, base, buf[:runtime.Stack(buf, true)])
}
