package kernel

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
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const testUUID = "4a86ae32-2235-4dc3-b103-42a2d162d73c"

func testCert(t *testing.T) (*TLSConfig, *x509.CertPool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if e = os.WriteFile(certPath, crt, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(crt)
	return &TLSConfig{Cert: certPath, Key: keyPath}, pool
}
func startTest(t *testing.T, in Inbound, modify func(*Config)) *Server {
	t.Helper()
	if in.Listen == "" {
		in.Listen = "127.0.0.1:0"
	}
	c := Config{UDPBindIPv4: "127.0.0.1", UDPBindIPv6: "::1", Inbounds: []Inbound{in}, Limits: Limits{Connections: 32, Handshakes: 16, Dials: 8, UDPAssociations: 8, UDPQueue: 4, UDPTargets: 4, PoolBuffers: 4, HandshakeTimeout: Duration(time.Second), DialTimeout: Duration(time.Second), DrainTimeout: Duration(2 * time.Second), UDPIdle: Duration(time.Second)}}
	// Existing end-to-end tests use loopback echo targets: allow them explicitly.
	c.Security = &SecurityOptions{AllowLoopback: true}
	if modify != nil {
		modify(&c)
	}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_ = s.Close(ctx)
		if got := s.Stats(); got.Active != 0 || got.Handshakes != 0 || got.Dials != 0 || got.UDP != 0 {
			t.Errorf("resource leak: %+v", got)
		}
	})
	return s
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not settle")
}
func sinkTCP(t *testing.T, network, address string, handler func(net.Conn)) Address {
	t.Helper()
	ln, e := net.Listen(network, address)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return addrFromNet(ln.Addr())
}
func echoTCP(t *testing.T) Address {
	return sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { _, _ = io.Copy(c, c) })
}
func echoUDP(t *testing.T) (Address, *net.UDPConn) {
	t.Helper()
	c, e := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = c.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	a := addrFromNet(c.LocalAddr())
	a.Host = "::1"
	return a, c
}
func dialPeer(t *testing.T, s *Server, pool *x509.CertPool) net.Conn {
	t.Helper()
	var c net.Conn
	var e error
	if pool != nil {
		c, e = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	} else {
		c, e = net.DialTimeout("tcp", s.Addresses()[0].String(), time.Second)
	}
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

// These are independent literal wire fixtures, not server parser/encoder round trips.
func peerAddr(a Address, vl bool) []byte {
	var b []byte
	ip := net.ParseIP(a.Host)
	if ip == nil {
		typ := byte(3)
		if vl {
			typ = 2
		}
		b = []byte{typ, byte(len(a.Host))}
		b = append(b, a.Host...)
	} else if x := ip.To4(); x != nil {
		b = append([]byte{1}, x...)
	} else {
		typ := byte(4)
		if vl {
			typ = 3
		}
		b = append([]byte{typ}, ip.To16()...)
	}
	if !vl {
		b = binary.BigEndian.AppendUint16(b, a.Port)
	}
	return b
}
func peerHeader(proto string, cmd byte, a Address) []byte {
	switch proto {
	case "socks5":
		return append([]byte{5, cmd, 0}, peerAddr(a, false)...)
	case "trojan":
		sum := sha256.Sum224([]byte("test-password"))
		b := []byte(hex.EncodeToString(sum[:]) + "\r\n")
		b = append(b, cmd)
		b = append(b, peerAddr(a, false)...)
		return append(b, 13, 10)
	case "vless":
		uuid, _ := hex.DecodeString(strings.ReplaceAll(testUUID, "-", ""))
		b := append([]byte{0}, uuid...)
		b = append(b, 0, cmd)
		b = binary.BigEndian.AppendUint16(b, a.Port)
		return append(b, peerAddr(a, true)...)
	}
	panic(proto)
}
func socksGreeting(t *testing.T, c net.Conn, auth bool, pass string) {
	t.Helper()
	method := byte(0)
	if auth {
		method = 2
	}
	if e := writeAll(c, []byte{5, 1, method}); e != nil {
		t.Fatal(e)
	}
	b, e := readN(c, 2)
	if e != nil || !bytes.Equal(b, []byte{5, method}) {
		t.Fatalf("greeting %x %v", b, e)
	}
	if auth {
		b = append([]byte{1, 4}, []byte("user")...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		writeAll(c, b)
		b, e = readN(c, 2)
		if e != nil || !bytes.Equal(b, []byte{1, 0}) {
			t.Fatalf("auth %x %v", b, e)
		}
	}
}
func peerResponse(t *testing.T, c net.Conn, p string) Address {
	t.Helper()
	if p == "socks5" {
		h, e := readN(c, 3)
		if e != nil || !bytes.Equal(h, []byte{5, 0, 0}) {
			t.Fatalf("SOCKS reply %x %v", h, e)
		}
		a, e := readAddress(c, false)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	if p == "vless" {
		b, e := readN(c, 2)
		if e != nil || !bytes.Equal(b, []byte{0, 0}) {
			t.Fatalf("VLESS response %x %v", b, e)
		}
	}
	return Address{}
}
func inFor(p string, tlsCfg *TLSConfig) Inbound {
	in := Inbound{Protocol: p, TLS: tlsCfg}
	switch p {
	case "trojan":
		in.Users = []User{{Password: "test-password"}}
	case "vless":
		in.Users = []User{{UUID: testUUID}}
	}
	return in
}
func TestTCPProtocols(t *testing.T) {
	cert, pool := testCert(t)
	for _, tc := range []struct {
		p    string
		tls  bool
		auth bool
		fast bool
	}{{"socks5", false, false, true}, {"socks5", false, true, false}, {"trojan", true, false, false}, {"vless", false, false, true}, {"vless", true, false, false}} {
		t.Run(fmt.Sprintf("%s-tls%v-auth%v", tc.p, tc.tls, tc.auth), func(t *testing.T) {
			var tlsCfg *TLSConfig
			var roots *x509.CertPool
			if tc.tls {
				tlsCfg = cert
				roots = pool
			}
			in := inFor(tc.p, tlsCfg)
			if tc.auth {
				in.Users = []User{{Username: "user", Password: "pass"}}
			}
			s := startTest(t, in, func(c *Config) { c.Limits.DisableFastPath = !tc.fast })
			target := echoTCP(t)
			for _, domain := range []bool{false, true} {
				a := target
				if domain {
					a.Host = "localhost"
				}
				c := dialPeer(t, s, roots)
				if tc.p == "socks5" {
					socksGreeting(t, c, tc.auth, "pass")
				}
				header := peerHeader(tc.p, 1, a)
				payload := []byte("first-payload\x00with-binary")
				for _, b := range header {
					if e := writeAll(c, []byte{b}); e != nil {
						t.Fatal(e)
					}
				}
				writeAll(c, payload)
				peerResponse(t, c, tc.p)
				got, e := readN(c, len(payload))
				if e != nil || !bytes.Equal(got, payload) {
					t.Fatalf("payload %x %v", got, e)
				}
				c.Close()
			}
			waitFor(t, func() bool { return s.Stats().Active == 0 })
		})
	}
}
func TestServerFirstAndHalfClose(t *testing.T) {
	cert, pool := testCert(t)
	for _, p := range []string{"socks5", "trojan", "vless"} {
		t.Run(p, func(t *testing.T) {
			var cfg *TLSConfig
			var roots *x509.CertPool
			if p == "trojan" {
				cfg = cert
				roots = pool
			}
			s := startTest(t, inFor(p, cfg), nil)
			target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
				writeAll(c, []byte("banner"))
				b, _ := io.ReadAll(c)
				if string(b) == "request" {
					writeAll(c, bytes.Repeat([]byte("z"), 512*1024))
				}
			})
			c := dialPeer(t, s, roots)
			if p == "socks5" {
				socksGreeting(t, c, false, "")
			}
			writeAll(c, peerHeader(p, 1, target))
			peerResponse(t, c, p)
			b, e := readN(c, 6)
			if e != nil || string(b) != "banner" {
				t.Fatalf("server-first %q %v", b, e)
			}
			writeAll(c, []byte("request"))
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			b, e = io.ReadAll(c)
			if e != nil || len(b) != 512*1024 || !bytes.Equal(b, bytes.Repeat([]byte("z"), 512*1024)) {
				t.Fatalf("half-close response length=%d %v", len(b), e)
			}
		})
	}
}
func peerUDPFrame(p string, a Address, payload []byte) []byte {
	var b []byte
	if p == "trojan" {
		b = peerAddr(a, false)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	if p == "trojan" {
		b = append(b, 13, 10)
	}
	return append(b, payload...)
}
func peerUDPRead(t *testing.T, c net.Conn, p string) []byte {
	t.Helper()
	if p == "trojan" {
		if _, e := readAddress(c, false); e != nil {
			t.Fatal(e)
		}
	}
	b, e := readN(c, 2)
	if e != nil {
		t.Fatal(e)
	}
	if p == "trojan" {
		if e = expectCRLF(c); e != nil {
			t.Fatal(e)
		}
	}
	b, e = readN(c, int(binary.BigEndian.Uint16(b)))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestStreamUDP(t *testing.T) {
	cert, pool := testCert(t)
	for _, tc := range []struct {
		p   string
		tls bool
	}{{"trojan", true}, {"vless", false}, {"vless", true}} {
		t.Run(fmt.Sprintf("%s-tls%v", tc.p, tc.tls), func(t *testing.T) {
			var cfg *TLSConfig
			var roots *x509.CertPool
			if tc.tls {
				cfg = cert
				roots = pool
			}
			s := startTest(t, inFor(tc.p, cfg), nil)
			target, _ := echoUDP(t)
			target.Host = "localhost"
			c := dialPeer(t, s, roots)
			cmd := byte(2)
			if tc.p == "trojan" {
				cmd = 3
			}
			writeAll(c, peerHeader(tc.p, cmd, target))
			peerResponse(t, c, tc.p)
			messages := [][]byte{[]byte("one"), {}, []byte("three"), bytes.Repeat([]byte("x"), 1200)}
			var combined []byte
			for _, m := range messages {
				combined = append(combined, peerUDPFrame(tc.p, target, m)...)
			}
			for len(combined) > 0 {
				n := min(3, len(combined))
				if e := writeAll(c, combined[:n]); e != nil {
					t.Fatal(e)
				}
				combined = combined[n:]
			}
			for _, m := range messages {
				if got := peerUDPRead(t, c, tc.p); !bytes.Equal(got, m) {
					t.Fatalf("UDP %x != %x", got, m)
				}
			}
			c.Close()
			waitFor(t, func() bool { return s.Stats().UDP == 0 && s.Stats().Active == 0 })
		})
	}
}
func socksAssociate(t *testing.T, s *Server, clientPort uint16) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	c := dialPeer(t, s, nil)
	socksGreeting(t, c, false, "")
	writeAll(c, peerHeader("socks5", 3, Address{"0.0.0.0", clientPort}))
	a := peerResponse(t, c, "socks5")
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { u.Close() })
	relay, e := net.ResolveUDPAddr("udp", a.String())
	if e != nil {
		t.Fatal(e)
	}
	return c, u, relay
}
func socksUDPSend(t *testing.T, u *net.UDPConn, relay *net.UDPAddr, a Address, p []byte, frag byte) {
	t.Helper()
	b := append([]byte{0, 0, frag}, peerAddr(a, false)...)
	b = append(b, p...)
	if _, e := u.WriteToUDP(b, relay); e != nil {
		t.Fatal(e)
	}
}
func socksUDPRead(t *testing.T, u *net.UDPConn) []byte {
	t.Helper()
	u.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 65535)
	n, _, e := u.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	r := bytes.NewReader(b[3:n])
	if _, e = readAddress(r, false); e != nil {
		t.Fatal(e)
	}
	p, _ := io.ReadAll(r)
	return p
}
func TestSOCKSUDPIsolationAndControl(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), nil)
	target, _ := echoUDP(t)
	c, u, relay := socksAssociate(t, s, 0)
	c2, u2, relay2 := socksAssociate(t, s, 0)
	socksUDPSend(t, u, relay, target, []byte("a"), 0)
	if string(socksUDPRead(t, u)) != "a" {
		t.Fatal("first UDP")
	}
	socksUDPSend(t, u2, relay2, target, []byte("b"), 0)
	if string(socksUDPRead(t, u2)) != "b" {
		t.Fatal("second UDP")
	}
	// Same IP, wrong source port must not hijack the already pinned association.
	socksUDPSend(t, u2, relay, target, []byte("forged"), 0)
	u2.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	b := make([]byte, 64)
	if _, _, e := u2.ReadFromUDP(b); e == nil {
		t.Fatal("cross-association packet accepted")
	}
	// Since 0.7.0 a lone first fragment waits for the rest of its datagram
	// (socks_frag_test.go); it is discarded when the association ends.
	socksUDPSend(t, u, relay, target, []byte("fragment"), 1)
	u.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	if _, _, e := u.ReadFromUDP(b); e == nil {
		t.Fatal("incomplete fragment forwarded")
	}
	socksUDPSend(t, u, relay, target, []byte("after"), 0)
	if string(socksUDPRead(t, u)) != "after" {
		t.Fatal("after drop")
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().UDP == 1 })
	socksUDPSend(t, u, relay, target, []byte("closed"), 0)
	u.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	if _, _, e := u.ReadFromUDP(b); e == nil {
		t.Fatal("closed association accepted")
	}
	c2.Close()
	waitFor(t, func() bool { return s.Stats().UDP == 0 })
	if s.Stats().Dropped < 1 || s.frags.dropped.Load() < 1 || s.frags.used.Load() != 0 {
		t.Fatal("drop not counted or fragment bytes kept")
	}
}
func TestUDPUnsolicitedSource(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), nil)
	target, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	forger, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer forger.Close()
	_, u, relay := socksAssociate(t, s, 0)
	socksUDPSend(t, u, relay, addrFromNet(target.LocalAddr()), []byte("request"), 0)
	target.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 128)
	_, out, e := target.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	forger.WriteToUDP([]byte("forged"), out)
	u.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	if _, _, e = u.ReadFromUDP(b); e == nil {
		t.Fatal("unsolicited source accepted")
	}
	target.WriteToUDP([]byte("valid"), out)
	if string(socksUDPRead(t, u)) != "valid" {
		t.Fatal("valid source rejected")
	}
}
func TestTLSAndCredentialsRejected(t *testing.T) {
	cert, pool := testCert(t)
	target := echoTCP(t)
	for _, p := range []string{"trojan", "vless"} {
		t.Run(p, func(t *testing.T) {
			s := startTest(t, inFor(p, cert), nil)
			for _, cfg := range []*tls.Config{{RootCAs: x509.NewCertPool(), ServerName: "localhost"}, {RootCAs: pool, ServerName: "wrong.invalid"}} {
				c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), cfg)
				if e == nil {
					c.Close()
					t.Fatal("bad certificate/SNI accepted")
				}
			}
			c := dialPeer(t, s, pool)
			h := peerHeader(p, 1, target)
			h[1] ^= 1
			writeAll(c, h)
			b := make([]byte, 1)
			if _, e := c.Read(b); e == nil {
				t.Fatal("bad credential accepted")
			}
			waitFor(t, func() bool { return s.Stats().Active == 0 })
		})
	}
}
func TestMalformedRequests(t *testing.T) {
	cert, pool := testCert(t)
	target := Address{"127.0.0.1", 9}
	for _, p := range []string{"trojan", "vless"} {
		var cfg *TLSConfig
		var roots *x509.CertPool
		if p == "trojan" {
			cfg = cert
			roots = pool
		}
		s := startTest(t, inFor(p, cfg), nil)
		base := peerHeader(p, 1, target)
		cases := [][]byte{base[:len(base)-1]}
		if p == "trojan" {
			x := bytes.Clone(base)
			x[56] = 0
			cases = append(cases, x)
			x = bytes.Clone(base)
			x[len(x)-1] = 0
			cases = append(cases, x)
			x = bytes.Clone(base)
			x[58] = 2
			cases = append(cases, x)
		} else {
			x := bytes.Clone(base)
			x[0] = 1
			cases = append(cases, x)
			x = bytes.Clone(base)
			x[18] = 4
			cases = append(cases, x)
			x = bytes.Clone(base)
			x[21] = 9
			cases = append(cases, x)
			x = append(bytes.Clone(base[:17]), 3, 10, 1, 120)
			x = append(x, base[18:]...)
			cases = append(cases, x)
		}
		for i, b := range cases {
			t.Run(fmt.Sprintf("%s-%d", p, i), func(t *testing.T) {
				c := dialPeer(t, s, roots)
				writeAll(c, b)
				c.(interface{ CloseWrite() error }).CloseWrite()
				out, e := io.ReadAll(c)
				if e == nil && len(out) > 0 {
					t.Fatalf("malformed accepted %x", out)
				}
				c.Close()
			})
		}
	}
	for _, b := range [][]byte{{0}, {10, 2, 1}, {8, 1}, {10, 1, 120}, {18, 1, 1}, {0x80}} {
		if validateAddons(b) == nil {
			t.Errorf("accepted addons %x", b)
		}
	}
	for _, b := range [][]byte{nil, {10, 0}, {24, 1}, {29, 0, 0, 0, 0}, {34, 2, 1, 2}} {
		if e := validateAddons(b); e != nil {
			t.Errorf("valid unknown/empty addons %x: %v", b, e)
		}
	}
}
func TestSOCKSAuthAndUnsupported(t *testing.T) {
	s := startTest(t, Inbound{Protocol: "socks5", Users: []User{{Username: "user", Password: "pass"}}}, nil)
	c := dialPeer(t, s, nil)
	writeAll(c, []byte{5, 1, 0})
	b, _ := readN(c, 2)
	if !bytes.Equal(b, []byte{5, 255}) {
		t.Fatal("auth downgrade")
	}
	c.Close()
	c = dialPeer(t, s, nil)
	writeAll(c, []byte{5, 1, 2})
	readN(c, 2)
	writeAll(c, []byte{1, 4, 117, 115, 101, 114, 3, 98, 97, 100})
	b, _ = readN(c, 2)
	if !bytes.Equal(b, []byte{1, 1}) {
		t.Fatal("bad password")
	}
	c.Close()
	n := startTest(t, inFor("socks5", nil), nil)
	for _, cmd := range []byte{2, 4} {
		c := dialPeer(t, n, nil)
		socksGreeting(t, c, false, "")
		writeAll(c, []byte{5, cmd, 0})
		b, _ := readN(c, 3)
		if len(b) != 3 || b[1] != 7 {
			t.Fatal("unsupported command")
		}
		c.Close()
	}
}
func TestLimitsTimeoutCancellation(t *testing.T) {
	baseline := runtime.NumGoroutine()
	s := startTest(t, inFor("socks5", nil), func(c *Config) {
		c.Limits.Connections = 2
		c.Limits.Handshakes = 1
		c.Limits.HandshakeTimeout = Duration(80 * time.Millisecond)
	})
	c := dialPeer(t, s, nil)
	waitFor(t, func() bool { return s.Stats().Handshakes == 1 })
	c2, e := net.Dial("tcp", s.Addresses()[0].String())
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if _, e = c2.Read(b); e == nil {
		t.Fatal("handshake limit")
	}
	waitFor(t, func() bool { return s.Stats().Active == 0 })
	c.Close()
	if s.Stats().Rejected == 0 {
		t.Fatal("no rejection")
	}
	target := echoTCP(t)
	c = dialPeer(t, s, nil)
	socksGreeting(t, c, false, "")
	writeAll(c, peerHeader("socks5", 1, target))
	peerResponse(t, c, "socks5")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e = s.Close(ctx); e == nil {
		t.Fatal("expected forced drain deadline")
	}
	if s.Stats().Active != 0 {
		t.Fatal("active leaked")
	}
	waitFor(t, func() bool { return runtime.NumGoroutine() <= baseline+4 })
}
func TestUDPIdleAndAssociationLimit(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.Limits.UDPAssociations = 1; c.Limits.UDPIdle = Duration(100 * time.Millisecond) })
	c, _, _ := socksAssociate(t, s, 0)
	c2 := dialPeer(t, s, nil)
	socksGreeting(t, c2, false, "")
	writeAll(c2, peerHeader("socks5", 3, Address{"0.0.0.0", 0}))
	b, e := readN(c2, 3)
	if e != nil || b[1] == 0 {
		t.Fatal("association limit")
	}
	c2.Close()
	waitFor(t, func() bool { return s.Stats().UDP == 0 && s.Stats().Active == 0 })
	c.Close()
}
func TestIPv6(t *testing.T) {
	probe, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	probe.Close()
	target := sinkTCP(t, "tcp6", "[::1]:0", func(c net.Conn) { io.Copy(c, c) })
	s := startTest(t, Inbound{Protocol: "vless", Listen: "[::1]:0", Users: []User{{UUID: testUUID}}}, nil)
	c := dialPeer(t, s, nil)
	writeAll(c, append(peerHeader("vless", 1, target), []byte("ipv6")...))
	peerResponse(t, c, "vless")
	b, e := readN(c, 4)
	if e != nil || string(b) != "ipv6" {
		t.Fatal("IPv6 failed", e)
	}
}
func TestAddressWireAndConfig(t *testing.T) {
	for _, a := range []Address{{"1.2.3.4", 443}, {"::1", 53}, {"localhost", 80}} {
		b := peerAddr(a, false)
		got, e := readAddress(bytes.NewReader(b), false)
		if e != nil || got != a {
			t.Fatalf("address %v %v", got, e)
		}
	}
	cases := []Config{{Inbounds: []Inbound{{Protocol: "socks5", Listen: "0.0.0.0:1080"}}}, {Inbounds: []Inbound{{Protocol: "vless", Listen: "0.0.0.0:1080", Users: []User{{UUID: testUUID}}}}}, {Inbounds: []Inbound{{Protocol: "trojan", Listen: "127.0.0.1:0", Users: []User{{Password: "secret"}}}}}, {Inbounds: []Inbound{{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: "bad"}}}}}}
	for _, c := range cases {
		if c.Validate() == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	for _, data := range []string{`{"inbounds":[],"secret":"do-not-print"}`, `{} {}`, `{"limits":{"handshake_timeout":"bad-secret"}}`} {
		p := filepath.Join(t.TempDir(), "bad.json")
		os.WriteFile(p, []byte(data), 0600)
		_, e := Load(p)
		if e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("config rejection or secrecy failed")
		}
	}
	p := newBufferPool(1024, 2)
	for range 8 {
		p.put(make([]byte, 1024))
	}
	if len(p.free) != 2 {
		t.Fatal("unbounded pool")
	}
	buf := p.get()
	buf[0] = 42
	p.put(buf)
	if p.get()[0] != 0 {
		t.Fatal("pool not cleared")
	}
}
func TestCurlIndependent(t *testing.T) {
	if _, e := exec.LookPath("curl"); e != nil {
		t.Fatal("curl required for independent SOCKS check")
	}
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		var b [4096]byte
		c.Read(b[:])
		writeAll(c, []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ncurl-check"))
	})
	for _, auth := range []bool{false, true} {
		in := inFor("socks5", nil)
		if auth {
			in.Users = []User{{Username: "user", Password: "pass"}}
		}
		s := startTest(t, in, nil)
		args := []string{"--fail", "--silent", "--show-error", "--noproxy", "", "--max-time", "3", "--socks5-hostname", s.Addresses()[0].String()}
		if auth {
			args = append(args, "--proxy-user", "user:pass")
		}
		args = append(args, "http://"+target.String()+"/")
		out, e := exec.Command("curl", args...).CombinedOutput()
		if e != nil || string(out) != "curl-check" {
			t.Fatalf("curl %v %q", e, out)
		}
	}
}
func TestResolveAndDialBudget(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.Limits.Dials = 1; c.Limits.DialTimeout = Duration(40 * time.Millisecond) })
	s.dialSlots.try()
	ctx := context.Background()
	if _, e := s.resolve(ctx, Address{"localhost", 53}); e == nil {
		t.Fatal("DNS quota ignored")
	}
	if _, e := s.dial(ctx, Address{"127.0.0.1", 9}); e == nil {
		t.Fatal("dial quota ignored")
	}
	s.dialSlots.release()
	if s.Stats().Dials != 0 {
		t.Fatal("dial resources leaked")
	}
	a, e := s.resolve(ctx, Address{"localhost", 53})
	if e != nil || !a.Addr().IsLoopback() {
		t.Fatal("DNS failed", e)
	}
}
func TestUDPQueueTargetBound(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &udpAssociation{server: s, ctx: ctx, queue: make(chan packet, 2)}
	for range 5 {
		a.enqueue(packet{payload: []byte("x")})
	}
	if len(a.queue) != 2 || s.Stats().Dropped != 3 {
		t.Fatal("queue not bounded")
	}
}
