// Package proxytest holds test-only helpers shared by the protocol outbound
// packages: loopback echo servers, self-signed certificates, real server
// processes (sing-box / kat, gated by environment variables) and a counting
// under-dialer. It is imported only from _test.go files.
package proxytest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// EchoTCP starts a loopback TCP echo server and returns its address.
func EchoTCP(t testing.TB) outbound.Addr {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(c, c)
			}()
		}
	}()
	p := ln.Addr().(*net.TCPAddr)
	return outbound.Addr{Host: "127.0.0.1", Port: uint16(p.Port)}
}

// EchoUDP starts a loopback UDP echo server (network "udp4" or "udp6").
func EchoUDP(t testing.TB, network string) outbound.Addr {
	t.Helper()
	host := "127.0.0.1"
	if network == "udp6" {
		host = "::1"
	}
	c, e := net.ListenPacket(network, net.JoinHostPort(host, "0"))
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	t.Cleanup(func() { c.Close(); <-done })
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			c.WriteTo(b[:n], a)
		}
	}()
	return outbound.Addr{Host: host, Port: uint16(c.LocalAddr().(*net.UDPAddr).Port)}
}

// Blackhole starts a loopback TCP server that accepts connections and never
// answers (a hung or silently-draining proxy server). It returns its port.
func Blackhole(t testing.TB) int {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-done
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go io.Copy(io.Discard, c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// FreePort returns a loopback port that is currently free for TCP and UDP.
func FreePort(t testing.TB) int {
	t.Helper()
	for range 50 {
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		u, e := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(port))
		ln.Close()
		if e == nil {
			u.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

// Cert is a self-signed loopback certificate (IP SANs 127.0.0.1, ::1; DNS localhost).
type Cert struct {
	CertPath, KeyPath string
	PinSHA256         string // hex SHA-256 of the leaf DER
}

// SelfSigned writes a fresh self-signed certificate into dir.
func SelfSigned(t testing.TB, dir string) Cert {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "kat-outbound-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	c := Cert{CertPath: filepath.Join(dir, "cert.pem"), KeyPath: filepath.Join(dir, "key.pem")}
	if e = os.WriteFile(c.CertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(der)
	c.PinSHA256 = hex.EncodeToString(sum[:])
	return c
}

// SingBox returns the sing-box binary from KAT_INTEROP_SINGBOX or skips.
func SingBox(t testing.TB) string {
	t.Helper()
	b := os.Getenv("KAT_INTEROP_SINGBOX")
	if b == "" {
		t.Skip("set KAT_INTEROP_SINGBOX to a sing-box binary to run interop tests")
	}
	return b
}

// Kat returns a locally built kat binary from KAT_INTEROP_KAT or skips.
func Kat(t testing.TB) string {
	t.Helper()
	b := os.Getenv("KAT_INTEROP_KAT")
	if b == "" {
		t.Skip("set KAT_INTEROP_KAT to a locally built ./cmd/kat to run interop tests")
	}
	return b
}

// StartSingBox runs sing-box with one inbound (listen 127.0.0.1:port) and a
// direct outbound. It returns the inbound port.
func StartSingBox(t testing.TB, inbound map[string]any) int {
	t.Helper()
	bin := SingBox(t)
	port := FreePort(t)
	inbound["tag"] = "in"
	inbound["listen"] = "127.0.0.1"
	inbound["listen_port"] = port
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	startProcess(t, "sing-box", cfg, port, func(path string) *exec.Cmd { return exec.Command(bin, "run", "-c", path) })
	return port
}

// StartKat runs the kat binary with one inbound (listen 127.0.0.1:port) and
// returns the port. inbound uses Kat's native inbound JSON.
func StartKat(t testing.TB, inbound map[string]any) int {
	t.Helper()
	bin := Kat(t)
	port := FreePort(t)
	inbound["listen"] = "127.0.0.1:" + strconv.Itoa(port)
	cfg := map[string]any{"udp_bind_ipv4": "127.0.0.1", "inbounds": []any{inbound}}
	startProcess(t, "kat", cfg, port, func(path string) *exec.Cmd { return exec.Command(bin, "run", path) })
	return port
}

func startProcess(t testing.TB, name string, cfg map[string]any, port int, cmdFor func(string) *exec.Cmd) {
	t.Helper()
	dir := t.TempDir()
	b, e := json.MarshalIndent(cfg, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, name+".json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	log := &bytes.Buffer{}
	var lmu sync.Mutex
	w := writerFunc(func(p []byte) (int, error) { lmu.Lock(); defer lmu.Unlock(); return log.Write(p) })
	cmd := cmdFor(path)
	cmd.Stdout, cmd.Stderr = w, w
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Logf("%s pid=%d port=%d", name, cmd.Process.Pid, port)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		lmu.Lock()
		defer lmu.Unlock()
		if log.Len() > 0 {
			out := log.Bytes()
			if len(out) > 4096 {
				out = out[len(out)-4096:]
			}
			t.Logf("%s pid=%d output (tail):\n%s", name, cmd.Process.Pid, out)
		}
	})
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for range 200 {
		c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s did not listen on %s", name, addr)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TCPEcho dials dst through d and verifies an echoed payload of size n.
func TCPEcho(t testing.TB, d outbound.Dialer, dst outbound.Addr, n int) {
	t.Helper()
	if e := TryTCPEcho(d, dst, n, 10*time.Second); e != nil {
		t.Fatalf("TCP echo via %T to %s: %v", d, dst, e)
	}
}

// TryTCPEcho is TCPEcho returning the error; the whole exchange is bounded by timeout.
func TryTCPEcho(d outbound.Dialer, dst outbound.Addr, n int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, e := d.DialTCP(ctx, dst)
	if e != nil {
		return fmt.Errorf("dial: %w", e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	payload := make([]byte, n)
	rand.Read(payload)
	errc := make(chan error, 1)
	go func() { _, e := c.Write(payload); errc <- e }()
	got := make([]byte, n)
	if _, e = io.ReadFull(c, got); e != nil {
		return fmt.Errorf("read: %w", e)
	}
	if e = <-errc; e != nil {
		return fmt.Errorf("write: %w", e)
	}
	if !bytes.Equal(got, payload) {
		return errors.New("echo mismatch")
	}
	// A second round on the same connection exercises steady-state records.
	if _, e = c.Write(payload[:min(n, 100)]); e != nil {
		return fmt.Errorf("write2: %w", e)
	}
	if _, e = io.ReadFull(c, got[:min(n, 100)]); e != nil {
		return fmt.Errorf("read2: %w", e)
	}
	if !bytes.Equal(got[:min(n, 100)], payload[:min(n, 100)]) {
		return errors.New("echo mismatch (round 2)")
	}
	return nil
}

// UDPEcho opens a PacketConn through d and verifies echoed datagrams.
func UDPEcho(t testing.TB, d outbound.Dialer, dst outbound.Addr) {
	t.Helper()
	if e := TryUDPEcho(d, dst, 5*time.Second); e != nil {
		t.Fatalf("UDP echo via %T to %s: %v", d, dst, e)
	}
}

// TryUDPEcho is UDPEcho returning the error. Each datagram is retried a few
// times (UDP may drop) within timeout.
func TryUDPEcho(d outbound.Dialer, dst outbound.Addr, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pc, e := d.ListenPacket(ctx)
	if e != nil {
		return fmt.Errorf("listen: %w", e)
	}
	defer pc.Close()
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)
	for i, size := range []int{1, 600, 1400} {
		payload := make([]byte, size)
		rand.Read(payload)
		ok := false
		for attempt := 0; attempt < 5 && !ok && time.Now().Before(deadline); attempt++ {
			if _, e = pc.WriteTo(payload, dst); e != nil {
				return fmt.Errorf("write %d: %w", i, e)
			}
			pc.SetReadDeadline(time.Now().Add(time.Second))
			for {
				n, src, e := pc.ReadFrom(buf)
				if e != nil {
					var ne net.Error
					if errors.As(e, &ne) && ne.Timeout() {
						break
					}
					return fmt.Errorf("read %d: %w", i, e)
				}
				if !bytes.Equal(buf[:n], payload) {
					continue // a late duplicate of an earlier datagram
				}
				if !sameAddr(src, dst) {
					return fmt.Errorf("datagram %d from %s, want %s", i, src, dst)
				}
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("no echo for datagram %d (%d bytes)", i, size)
		}
	}
	return nil
}

func sameAddr(a, b outbound.Addr) bool {
	x, e1 := netip.ParseAddr(a.Host)
	y, e2 := netip.ParseAddr(b.Host)
	if e1 == nil && e2 == nil {
		return x.Unmap() == y.Unmap() && a.Port == b.Port
	}
	if e2 != nil {
		// Name destination: the last hop reports the resolved IP.
		return a.Port == b.Port
	}
	return a == b
}

// Counter wraps an under-dialer and records every destination it is asked
// to reach (TCP dials and datagram WriteTo).
type Counter struct {
	Under outbound.Dialer
	mu    sync.Mutex
	tcp   []outbound.Addr
	udp   []outbound.Addr
	lists int
}

func (c *Counter) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	c.mu.Lock()
	c.tcp = append(c.tcp, dst)
	c.mu.Unlock()
	return c.Under.DialTCP(ctx, dst)
}

func (c *Counter) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	c.mu.Lock()
	c.lists++
	c.mu.Unlock()
	pc, e := c.Under.ListenPacket(ctx)
	if e != nil {
		return nil, e
	}
	return &countingPC{PacketConn: pc, c: c}, nil
}

func (c *Counter) UDP() bool { return c.Under.UDP() }

// Snapshot returns copies of the recorded destinations.
func (c *Counter) Snapshot() (tcp, udp []outbound.Addr, lists int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]outbound.Addr(nil), c.tcp...), append([]outbound.Addr(nil), c.udp...), c.lists
}

type countingPC struct {
	outbound.PacketConn
	c *Counter
}

func (p *countingPC) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	p.c.mu.Lock()
	p.c.udp = append(p.c.udp, dst)
	p.c.mu.Unlock()
	return p.PacketConn.WriteTo(b, dst)
}

// TCPOnly is an under-dialer that cannot carry UDP.
type TCPOnly struct{ Under outbound.Dialer }

func (d TCPOnly) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	return d.Under.DialTCP(ctx, dst)
}
func (d TCPOnly) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (d TCPOnly) UDP() bool { return false }
