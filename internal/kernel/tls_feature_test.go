package kernel

import (
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
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/tlscert"
)

var testSerial int64 = 1000

// writeTestCert writes a self-signed certificate for names into dir/base.{crt,key}
// and returns the file paths and the serial number.
func writeTestCert(t *testing.T, dir, base string, names ...string) (string, string, int64) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	testSerial++
	serial := testSerial
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	cp, kp := filepath.Join(dir, base+".crt"), filepath.Join(dir, base+".key")
	// Write through a temporary file and rename, like certificate managers do.
	for _, f := range []struct {
		path string
		data []byte
	}{{cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, {kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})}} {
		if e := os.WriteFile(f.path+".tmp", f.data, 0o600); e != nil {
			t.Fatal(e)
		}
		if e := os.Rename(f.path+".tmp", f.path); e != nil {
			t.Fatal(e)
		}
	}
	return cp, kp, serial
}

// trojanEchoStart sends a Trojan CONNECT to the echo sink at a with the first
// payload and checks the echo; later checks use trojanEchoAgain.
func trojanEchoStart(t *testing.T, c net.Conn, a Address, msg string) {
	t.Helper()
	sum := sha256.Sum224([]byte("pw"))
	h := []byte(hex.EncodeToString(sum[:]) + "\r\n")
	ip := net.ParseIP(a.Host).To4()
	h = append(h, 1, 1)
	h = append(h, ip...)
	h = append(h, byte(a.Port>>8), byte(a.Port), '\r', '\n')
	if _, e := c.Write(append(h, msg...)); e != nil {
		t.Fatal(e)
	}
	trojanEchoRead(t, c, msg)
}

func trojanEchoRead(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, len(msg))
	if _, e := io.ReadFull(c, b); e != nil || string(b) != msg {
		t.Fatalf("echo through held connection: %v %q", e, b)
	}
}

func echoSink(t *testing.T) Address {
	return sinkTCP(t, "tcp", "127.0.0.1:0", func(c net.Conn) { io.Copy(c, c) })
}

func trojanTLSInbound(listen string, t *TLSConfig) Inbound {
	return Inbound{Protocol: "trojan", Listen: listen, TLS: t, Users: []User{{Password: "pw"}}}
}

// peerSerial completes a TLS handshake with sni and returns the leaf serial.
func peerSerial(t *testing.T, addr, sni string) (int64, *tls.Conn) {
	t.Helper()
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if e != nil {
		t.Fatal(e)
	}
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), c
}

func TestServerTLSSNISelectionAndDefault(t *testing.T) {
	dir := t.TempDir()
	ac, ak, as := writeTestCert(t, dir, "a", "a.example")
	bc, bk, bs := writeTestCert(t, dir, "b", "b.example", "*.b.example")
	s := startTest(t, trojanTLSInbound("", &TLSConfig{Cert: ac, Key: ak, Certificates: []TLSCertFile{{bc, bk}}}), nil)
	addr := s.Addresses()[0].String()
	for _, tc := range []struct {
		sni  string
		want int64
	}{{"a.example", as}, {"b.example", bs}, {"x.b.example", bs}, {"unknown.example", as}, {"", as}} {
		got, c := peerSerial(t, addr, tc.sni)
		c.Close()
		if got != tc.want {
			t.Errorf("SNI %q: serial %d, want %d", tc.sni, got, tc.want)
		}
	}
}

func readLog(t *testing.T, path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestServerTLSWatchReplacesAndRefuses(t *testing.T) {
	old := tlscert.SettleDelay
	tlscert.SettleDelay = 10 * time.Millisecond
	defer func() { tlscert.SettleDelay = old }()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "kat.log")
	cp, kp, s1 := writeTestCert(t, dir, "a", "a.example")
	s := startTest(t, trojanTLSInbound("", &TLSConfig{Cert: cp, Key: kp, Watch: true, WatchInterval: Duration(time.Second)}), func(c *Config) {
		c.Log = &LogOptions{File: logFile}
	})
	addr := s.Addresses()[0].String()
	echo := echoSink(t)
	got, held := peerSerial(t, addr, "a.example")
	defer held.Close()
	if got != s1 {
		t.Fatalf("serial %d want %d", got, s1)
	}
	trojanEchoStart(t, held, echo, "before")
	_, _, s2 := writeTestCert(t, dir, "a", "a.example")
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, c := peerSerial(t, addr, "a.example")
		c.Close()
		if got == s2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watched certificate not replaced")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The connection established with the first certificate still relays.
	held.Write([]byte("after-swap"))
	trojanEchoRead(t, held, "after-swap")
	// A broken pair is refused with a warning; the previous one stays.
	if e := os.WriteFile(cp, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	waitLog := func(sub string) {
		end := time.Now().Add(5 * time.Second)
		for !strings.Contains(readLog(t, logFile), sub) {
			if time.Now().After(end) {
				t.Fatalf("log lacks %q:\n%s", sub, readLog(t, logFile))
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitLog("event=tls_certificate_reload_failed source=watch")
	held.Write([]byte("after-refusal"))
	trojanEchoRead(t, held, "after-refusal")
	if got, c := peerSerial(t, addr, "a.example"); got != s2 {
		t.Fatalf("after refused pair serial %d want %d", got, s2)
	} else {
		c.Close()
	}
	if !strings.Contains(readLog(t, logFile), "event=tls_certificate_reloaded source=watch") {
		t.Fatal("replacement not logged")
	}
}

func TestServerTLSReloadSwapsAndRefusesCertificate(t *testing.T) {
	dir := t.TempDir()
	cp, kp, s1 := writeTestCert(t, dir, "a", "a.example")
	c := Config{Inbounds: []Inbound{trojanTLSInbound(reloadPort(t), &TLSConfig{Cert: cp, Key: kp})}, Limits: reloadLimits()}
	next := c
	next.Inbounds = []Inbound{trojanTLSInbound(c.Inbounds[0].Listen, &TLSConfig{Cert: cp, Key: kp})}
	c.Security = &SecurityOptions{AllowLoopback: true}
	next.Security = c.Security
	s := startReloadable(t, c, &next)
	addr := s.Addresses()[0].String()
	echo := echoSink(t)
	got, held := peerSerial(t, addr, "a.example")
	defer held.Close()
	if got != s1 {
		t.Fatal("initial certificate")
	}
	trojanEchoStart(t, held, echo, "before")
	_, _, s2 := writeTestCert(t, dir, "a", "a.example")
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if got, c := peerSerial(t, addr, "a.example"); got != s2 {
		t.Fatalf("after reload serial %d want %d", got, s2)
	} else {
		c.Close()
	}
	held.Write([]byte("after-reload"))
	trojanEchoRead(t, held, "after-reload")
	os.WriteFile(kp, []byte("broken"), 0o600)
	if _, e := s.Reload("test"); e == nil || !strings.Contains(e.Error(), "cannot load TLS certificate/key") {
		t.Fatalf("broken key reload: %v", e)
	}
	if got, c := peerSerial(t, addr, "a.example"); got != s2 {
		t.Fatal("refused reload changed the certificate")
	} else {
		c.Close()
	}
}

func TestServerTLSParameters(t *testing.T) {
	dir := t.TempDir()
	cp, kp, _ := writeTestCert(t, dir, "a", "a.example")
	s := startTest(t, trojanTLSInbound("", &TLSConfig{Cert: cp, Key: kp, ALPN: []string{"h2", "http/1.1"}, MaxVersion: "1.2", CipherSuites: []string{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"}}), nil)
	addr := s.Addresses()[0].String()
	c, e := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if e != nil {
		t.Fatal(e)
	}
	st := c.ConnectionState()
	c.Close()
	if st.Version != tls.VersionTLS12 || st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 || st.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("negotiated %x %x %q", st.Version, st.CipherSuite, st.NegotiatedProtocol)
	}
	if c, e := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}); e == nil {
		c.Close()
		t.Fatal("TLS 1.3 client accepted by max_version 1.2")
	}
	if c, e := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, MaxVersion: tls.VersionTLS12}); e == nil {
		c.Close()
		t.Fatal("cipher suite outside the list accepted")
	}
	s13 := startTest(t, trojanTLSInbound("", &TLSConfig{Cert: cp, Key: kp, MinVersion: "1.3"}), nil)
	if c, e := tls.Dial("tcp", s13.Addresses()[0].String(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}); e == nil {
		c.Close()
		t.Fatal("TLS 1.2 client accepted by min_version 1.3")
	}
}

func TestServerTLSValidation(t *testing.T) {
	dir := t.TempDir()
	cp, kp, _ := writeTestCert(t, dir, "a", "a.example")
	bad := []*TLSConfig{
		{Cert: cp, Key: kp, MinVersion: "1.1"},
		{Cert: cp, Key: kp, MinVersion: "1.3", MaxVersion: "1.2"},
		{Cert: cp, Key: kp, MinVersion: "1.3", CipherSuites: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}},
		{Cert: cp, Key: kp, CipherSuites: []string{"TLS_RSA_WITH_RC4_128_SHA"}},
		{Cert: cp, Key: kp, ALPN: []string{"acme-tls/1"}},
		{Cert: cp, Key: kp, WatchInterval: Duration(time.Second)},
		{Cert: cp, Key: kp, Watch: true, WatchInterval: Duration(time.Millisecond)},
		{Cert: cp},
		{Cert: cp, Key: kp, Certificates: []TLSCertFile{{Cert: cp}}},
		{ACME: &ACMEConfig{Domains: []string{"a.example"}}},
		{ACME: &ACMEConfig{Domains: []string{"*.a.example"}, Challenge: "http-01"}},
		{ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "dns-01"}},
		{ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "dns-01", DNS: &ACMEDNS{Provider: "cloudflare", APIToken: "x", APITokenFile: "/x"}}},
		{ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "http-01", Webroot: "rel"}},
		{ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "tls-alpn-01", Directory: "http://ca.example/dir"}},
		{ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "tls-alpn-01", EAB: &ACMEEAB{KeyID: "k"}}},
	}
	for i, tc := range bad {
		in := trojanTLSInbound("127.0.0.1:0", tc)
		c := Config{Inbounds: []Inbound{in}}
		if e := c.Validate(); e == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	good := []*TLSConfig{
		{Cert: cp, Key: kp, Watch: true},
		{ACME: &ACMEConfig{Domains: []string{"A.Example"}, Challenge: "tls-alpn-01", EAB: &ACMEEAB{KeyID: "k", MACKey: "c2VjcmV0"}}},
		{ACME: &ACMEConfig{Domains: []string{"*.a.example", "a.example"}, Challenge: "dns-01", DNS: &ACMEDNS{Provider: "cloudflare", APIToken: "x"}}},
		{Cert: cp, Key: kp, ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "http-01", HTTPListen: "127.0.0.1:8080"}},
	}
	for i, tc := range good {
		c := Config{Inbounds: []Inbound{trojanTLSInbound("127.0.0.1:0", tc)}}
		if e := c.Validate(); e != nil {
			t.Errorf("good case %d: %v", i, e)
		}
	}
	// Extended options are refused on VLESS.
	c := Config{Inbounds: []Inbound{{Protocol: "vless", Listen: "127.0.0.1:0", TLS: &TLSConfig{Cert: cp, Key: kp, ALPN: []string{"h2"}}, Users: []User{{UUID: testUUID}}}}}
	if e := c.Validate(); e == nil {
		t.Error("VLESS accepted extended TLS options")
	}
	// ACME without storage cannot start (the CLI sets the default).
	c = Config{Inbounds: []Inbound{trojanTLSInbound("127.0.0.1:0", &TLSConfig{ACME: &ACMEConfig{Domains: []string{"a.example"}, Challenge: "tls-alpn-01"}})}}
	if s, e := Start(c); e == nil {
		s.Close(t.Context())
		t.Error("ACME without storage started")
	}
}

func TestTFOWarnings(t *testing.T) {
	in := Config{Inbounds: []Inbound{{TCPFastOpen: true}}}
	dir := Config{Direct: &DirectOptions{TCPFastOpen: true}}
	both := Config{Inbounds: []Inbound{{TCPFastOpen: true}}, Direct: &DirectOptions{TCPFastOpen: true}}
	val := func(v int) func() (int, error) { return func() (int, error) { return v, nil } }
	cases := []struct {
		c    *Config
		v    int
		want []string
	}{
		{&Config{}, 0, nil},
		{&in, 1, []string{"side=server"}},
		{&in, 2, nil},
		{&in, 3, nil},
		{&dir, 0, []string{"side=client"}},
		{&dir, 1, nil},
		{&dir, 2, []string{"side=client"}},
		{&both, 0, []string{"side=server", "side=client"}},
		{&both, 3, nil},
	}
	for i, tc := range cases {
		got := tfoWarnings(tc.c, val(tc.v))
		if len(got) != len(tc.want) {
			t.Fatalf("case %d: %q", i, got)
		}
		for j := range got {
			if !strings.Contains(got[j], tc.want[j]) || !strings.Contains(got[j], "event=tfo_sysctl_insufficient") {
				t.Fatalf("case %d: %q", i, got)
			}
		}
	}
	if got := tfoWarnings(&in, func() (int, error) { return 0, errors.New("x") }); len(got) != 1 || !strings.Contains(got[0], "tfo_sysctl_unreadable") {
		t.Fatalf("unreadable: %q", got)
	}
}

func TestTFOListenerAndDirectRelay(t *testing.T) {
	if !tfoSupported {
		t.Skip("linux only")
	}
	echo := sinkTCP(t, "tcp", "127.0.0.1:0", func(c net.Conn) {
		b := make([]byte, 4)
		if n, e := c.Read(b); e == nil {
			c.Write(b[:n])
		}
	})
	s := startTest(t, Inbound{Protocol: "socks5", TCPFastOpen: true}, func(c *Config) { c.Direct = &DirectOptions{TCPFastOpen: true} })
	if c, ok := socksTo(t, s.Addresses()[0].String(), echo); !ok || !echoOnce(c, "ping") {
		t.Fatal("relay with TFO enabled failed")
	} else {
		c.Close()
	}
	e := s.core.tcpEntries[listenKey(s.CurrentConfig().Inbounds[0].Listen)+"#0"]
	if e == nil || !e.tfo {
		t.Fatal("listener TFO state not recorded")
	}
}
