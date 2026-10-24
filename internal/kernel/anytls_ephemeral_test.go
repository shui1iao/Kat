package kernel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if e := os.WriteFile(p, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}

func anyTLSJSON(tlsMember string) string {
	m := `"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"ephemeral-test"}`
	if tlsMember != "" {
		m += "," + tlsMember
	}
	return `{"inbounds":[{` + m + `}]}`
}

func ephemeralLeaf(t *testing.T, in *Inbound) *tls.Certificate {
	t.Helper()
	if !in.ephemeralTLS || in.tlsConfig == nil || len(in.tlsConfig.Certificates) != 1 {
		t.Fatalf("no ephemeral certificate: ephemeral=%v cfg=%v", in.ephemeralTLS, in.tlsConfig != nil)
	}
	return &in.tlsConfig.Certificates[0]
}

func TestAnyTLSOmittedTLSUsesEphemeralCertificate(t *testing.T) {
	before := time.Now()
	c1, e := Load(writeConfig(t, anyTLSJSON("")))
	if e != nil {
		t.Fatal(e)
	}
	in := &c1.Inbounds[0]
	if in.TLS != nil || in.tlsWritten {
		t.Fatal("omitted tls decoded as written")
	}
	cert := ephemeralLeaf(t, in)
	leaf := cert.Leaf
	if leaf == nil || len(cert.Certificate) != 1 || !bytes.Equal(leaf.Raw, cert.Certificate[0]) {
		t.Fatal("leaf missing")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("not ECDSA P-256: %T", leaf.PublicKey)
	}
	if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() < 64 {
		t.Fatalf("serial not random-sized: %v", leaf.SerialNumber)
	}
	nb, na := leaf.NotBefore, leaf.NotAfter
	if nb.After(before.Add(-time.Hour+time.Second)) || nb.Before(before.Add(-time.Hour-5*time.Second)) {
		t.Fatalf("NotBefore %v not now-1h", nb)
	}
	if want := before.AddDate(10, 0, 0); na.Before(want.Add(-5*time.Second)) || na.After(want.Add(5*time.Second)) {
		t.Fatalf("NotAfter %v not now+10y", na)
	}
	if leaf.Subject.CommonName != "localhost" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA {
		t.Fatalf("unexpected names: %+v %v %v", leaf.Subject, leaf.DNSNames, leaf.IPAddresses)
	}
	host, _ := os.Hostname()
	for _, s := range []string{leaf.Subject.String(), leaf.Issuer.String(), strings.Join(leaf.DNSNames, ",")} {
		if strings.Contains(strings.ToLower(s), "kat") || host != "" && host != "localhost" && strings.Contains(s, host) {
			t.Fatalf("identifying name %q", s)
		}
	}
	tc := in.tlsConfig
	if tc.MinVersion != tls.VersionTLS12 || tc.MaxVersion != 0 || len(tc.NextProtos) != 0 {
		t.Fatalf("TLS parameters differ from file path: min=%x max=%x alpn=%v", tc.MinVersion, tc.MaxVersion, tc.NextProtos)
	}

	// A second load generates a different certificate and key.
	c2, e := Load(writeConfig(t, anyTLSJSON("")))
	if e != nil {
		t.Fatal(e)
	}
	cert2 := ephemeralLeaf(t, &c2.Inbounds[0])
	if bytes.Equal(cert.Certificate[0], cert2.Certificate[0]) || cert.Leaf.SerialNumber.Cmp(cert2.Leaf.SerialNumber) == 0 ||
		cert.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(cert2.Leaf.PublicKey) {
		t.Fatal("two loads produced the same certificate/serial/key")
	}

	// Start re-validates the loaded config and serves the same certificate.
	s, e := Start(c1)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	}()
	conn, e := tls.Dial("tcp", s.Addresses()[0].String(), &tls.Config{InsecureSkipVerify: true})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) != 1 || !bytes.Equal(st.PeerCertificates[0].Raw, cert.Certificate[0]) {
		t.Fatal("served certificate is not the one generated at load")
	}
	// Default verification must reject it (self-signed).
	if c, e := tls.Dial("tcp", s.Addresses()[0].String(), &tls.Config{ServerName: "localhost"}); e == nil {
		c.Close()
		t.Fatal("self-signed ephemeral certificate verified without insecure")
	}
}

func TestAnyTLSWrittenTLSStaysStrict(t *testing.T) {
	file, _ := testCert(t)
	q := func(s string) string { return strconv.Quote(s) }
	for _, tc := range []struct{ name, member, err string }{
		{"null", `"tls":null`, "AnyTLS requires TLS and single password options"},
		{"case-variant null", `"TLS":null`, "AnyTLS requires TLS and single password options"},
		{"duplicate ending in null", `"tls":{"cert":` + q(file.Cert) + `,"key":` + q(file.Key) + `},"tls":null`, "AnyTLS requires TLS and single password options"},
		{"empty object", `"tls":{}`, "cannot load TLS certificate/key"},
		{"cert only", `"tls":{"cert":` + q(file.Cert) + `}`, "cannot load TLS certificate/key"},
		{"key only", `"tls":{"key":` + q(file.Key) + `}`, "cannot load TLS certificate/key"},
		{"empty strings", `"tls":{"cert":"","key":""}`, "cannot load TLS certificate/key"},
		{"missing files", `"tls":{"cert":"/nonexistent/c.pem","key":"/nonexistent/k.pem"}`, "cannot load TLS certificate/key"},
	} {
		_, e := Load(writeConfig(t, anyTLSJSON(tc.member)))
		if e == nil || e.Error() != tc.err {
			t.Fatalf("%s: got %v want %q", tc.name, e, tc.err)
		}
	}
	// Written tls with a loadable pair: unchanged file-certificate path.
	c, e := Load(writeConfig(t, anyTLSJSON(`"tls":{"cert":`+q(file.Cert)+`,"key":`+q(file.Key)+`}`)))
	if e != nil {
		t.Fatal(e)
	}
	in := c.Inbounds[0]
	if in.ephemeralTLS || in.tlsConfig == nil || in.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("file certificate path changed")
	}
	want, _ := tls.LoadX509KeyPair(file.Cert, file.Key)
	if !bytes.Equal(in.tlsConfig.Certificates[0].Certificate[0], want.Certificate[0]) {
		t.Fatal("file certificate not used")
	}
	// Users are still rejected when tls is omitted.
	if _, e := Load(writeConfig(t, `{"inbounds":[{"protocol":"anytls","listen":"127.0.0.1:0","users":[{"password":"x"}],"anytls":{"password":"y"}}]}`)); e == nil {
		t.Fatal("AnyTLS users accepted")
	}
	// Unknown fields are still rejected inside an inbound.
	if _, e := Load(writeConfig(t, anyTLSJSON(`"self_signed":true`))); e == nil || e.Error() != "invalid configuration JSON or unknown field" {
		t.Fatalf("unknown inbound field: %v", e)
	}
}

func TestOtherProtocolsTLSRulesUnchanged(t *testing.T) {
	file, _ := testCert(t)
	q := strconv.Quote
	for _, tc := range []struct{ name, cfg, err string }{
		{"trojan omitted", `{"inbounds":[{"protocol":"trojan","listen":"127.0.0.1:0","users":[{"password":"p"}]}]}`, "Trojan requires TLS and password users"},
		{"trojan null", `{"inbounds":[{"protocol":"trojan","listen":"127.0.0.1:0","users":[{"password":"p"}],"tls":null}]}`, "Trojan requires TLS and password users"},
		{"trojan empty", `{"inbounds":[{"protocol":"trojan","listen":"127.0.0.1:0","users":[{"password":"p"}],"tls":{}}]}`, "cannot load TLS certificate/key"},
		{"socks tls", `{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0","tls":{"cert":` + q(file.Cert) + `,"key":` + q(file.Key) + `}}]}`, "SOCKS5 TLS wrapper is not implemented"},
	} {
		_, e := Load(writeConfig(t, tc.cfg))
		if e == nil || e.Error() != tc.err {
			t.Fatalf("%s: got %v want %q", tc.name, e, tc.err)
		}
	}
	// No other protocol receives an ephemeral certificate.
	c, e := Load(writeConfig(t, `{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"},{"protocol":"vless","listen":"127.0.0.1:0","users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}`))
	if e != nil {
		t.Fatal(e)
	}
	for i, in := range c.Inbounds {
		if in.tlsConfig != nil || in.ephemeralTLS {
			t.Fatalf("inbound %d got a TLS config", i)
		}
	}
	c, e = Load(writeConfig(t, `{"inbounds":[{"protocol":"trojan","listen":"127.0.0.1:0","users":[{"password":"p"}],"tls":{"cert":`+q(file.Cert)+`,"key":`+q(file.Key)+`}}]}`))
	if e != nil || c.Inbounds[0].ephemeralTLS || c.Inbounds[0].tlsConfig == nil {
		t.Fatalf("trojan with tls: %v", e)
	}
}
