package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func pemPair(t *testing.T, serial int64, notAfter time.Time, names ...string) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notAfter.Add(-2 * time.Hour), NotAfter: notAfter}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

func TestFilePairCheck(t *testing.T) {
	SettleDelay = 0
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c"), filepath.Join(dir, "k")
	write := func(c, k []byte) {
		os.WriteFile(cp, c, 0o600)
		os.WriteFile(kp, k, 0o600)
	}
	c1, k1 := pemPair(t, 1, time.Now().Add(time.Hour), "a.example")
	write(c1, k1)
	cert, sum, e := LoadPair(cp, kp)
	if e != nil {
		t.Fatal(e)
	}
	f := NewFilePair(cp, kp, cert, sum)
	if r, _ := f.Check(time.Now()); r != Unchanged {
		t.Fatal("unchanged pair reported", r)
	}
	c2, k2 := pemPair(t, 2, time.Now().Add(time.Hour), "a.example")
	write(c2, k2)
	if r, e := f.Check(time.Now()); r != Replaced || e != nil || f.Certificate().Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("replacement", r, e)
	}
	// Mismatched key: refused once, previous kept.
	os.WriteFile(kp, k1, 0o600)
	if r, e := f.Check(time.Now()); r != Refused || e == nil || f.Certificate().Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("mismatch", r, e)
	}
	if r, _ := f.Check(time.Now()); r != Unchanged {
		t.Fatal("refusal reported twice", r)
	}
	// Expired certificate refused.
	c3, k3 := pemPair(t, 3, time.Now().Add(-time.Minute), "a.example")
	write(c3, k3)
	if r, e := f.Check(time.Now()); r != Refused || !strings.Contains(e.Error(), "expired") {
		t.Fatal("expired", r, e)
	}
	// Missing file: refused once.
	os.Remove(kp)
	if r, _ := f.Check(time.Now()); r != Refused {
		t.Fatal("missing", r)
	}
	if r, _ := f.Check(time.Now()); r != Unchanged {
		t.Fatal("missing twice", r)
	}
	write(c2, k2)
	if r, _ := f.Check(time.Now()); r != Unchanged || f.Certificate().Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("restored identical content", r)
	}
}

type fixed struct{ c *tls.Certificate }

func (f fixed) Certificate() *tls.Certificate { return f.c }

func TestSelector(t *testing.T) {
	mk := func(serial int64, names ...string) *tls.Certificate {
		c, k := pemPair(t, serial, time.Now().Add(time.Hour), names...)
		p, e := ParsePair(c, k)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	a, b, fb := mk(1, "a.example"), mk(2, "*.b.example"), mk(3, "fallback")
	s := &Selector{Sources: []Source{fixed{nil}, fixed{a}, fixed{b}}, Fallback: fb}
	for name, want := range map[string]int64{"a.example": 1, "x.b.example": 2, "B.EXAMPLE.": 1, "": 1, "other": 1} {
		if got := s.Pick(name).Leaf.SerialNumber.Int64(); got != want {
			t.Errorf("%q -> %d want %d", name, got, want)
		}
	}
	if (&Selector{Sources: []Source{fixed{nil}}, Fallback: fb}).Pick("a.example") != fb {
		t.Error("fallback not used")
	}
}

func TestSelectorPickHelloKeyType(t *testing.T) {
	c1, k1 := pemPair(t, 1, time.Now().Add(time.Hour), "p.example")
	ec, e := ParsePair(c1, k1)
	if e != nil {
		t.Fatal(e)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "p.example"}, DNSNames: []string{"p.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &rk.PublicKey, rk)
	kb, _ := x509.MarshalPKCS8PrivateKey(rk)
	rs, e := ParsePair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	if e != nil {
		t.Fatal(e)
	}
	s := &Selector{Sources: []Source{fixed{ec}, fixed{rs}}}
	h := func(suite uint16) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{ServerName: "p.example", CipherSuites: []uint16{suite}, SupportedVersions: []uint16{tls.VersionTLS12},
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256, tls.PKCS1WithSHA256}, SupportedCurves: []tls.CurveID{tls.CurveP256}, SupportedPoints: []uint8{0}}
	}
	if got := s.PickHello(h(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)).Leaf.SerialNumber.Int64(); got != 2 {
		t.Fatal("RSA-only client got", got)
	}
	if got := s.PickHello(h(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)).Leaf.SerialNumber.Int64(); got != 1 {
		t.Fatal("ECDSA client got", got)
	}
	if got := s.PickHello(&tls.ClientHelloInfo{ServerName: "unknown"}).Leaf.SerialNumber.Int64(); got != 1 {
		t.Fatal("unknown name got", got)
	}
}

func TestBackoff(t *testing.T) {
	day := 24 * time.Hour
	if backoff(1, 90*day) != time.Minute || backoff(20, 90*day) != 6*time.Hour {
		t.Fatal("90d", backoff(1, 90*day), backoff(20, 90*day))
	}
	if backoff(1, 6*time.Minute) != 18*time.Second || backoff(2, 6*time.Minute) != 36*time.Second || backoff(5, 6*time.Minute) != time.Minute {
		t.Fatal("6m", backoff(1, 6*time.Minute), backoff(2, 6*time.Minute), backoff(5, 6*time.Minute))
	}
	if backoff(1, 30*time.Second) != 5*time.Second || backoff(9, 30*time.Second) != 5*time.Second {
		t.Fatal("30s")
	}
}

func TestRenewAt(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}
	if got := RenewAt(leaf); !got.Equal(nb.Add(60 * 24 * time.Hour)) {
		t.Fatal(got)
	}
}

func TestStorageNames(t *testing.T) {
	if got := caDirName("https://acme-staging-v02.api.letsencrypt.org/directory"); got != "acme-staging-v02.api.letsencrypt.org-directory" {
		t.Fatal(got)
	}
	if got := caDirName("https://127.0.0.1:14000/dir"); got != "127.0.0.1_14000-dir" {
		t.Fatal(got)
	}
	m, e := NewManager(Options{Domains: []string{"*.a.example", "a.example"}, Storage: t.TempDir(), Challenge: ChallengeDNS01}, Hooks{})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasSuffix(m.certDir(), filepath.Join("acme-v02.api.letsencrypt.org-directory", "certificates", "_wildcard_.a.example")) {
		t.Fatal(m.certDir())
	}
	if m.Certificate() != nil {
		t.Fatal("certificate without storage")
	}
	if _, e := NewManager(Options{Domains: []string{"a.example"}, Storage: "rel"}, Hooks{}); e == nil {
		t.Fatal("relative storage accepted")
	}
}

func TestManagerLoadsStoredCertificate(t *testing.T) {
	dir := t.TempDir()
	o := Options{Domains: []string{"a.example"}, Storage: dir, Directory: "https://ca.example/dir", Challenge: ChallengeTLSALPN01}
	m, _ := NewManager(o, Hooks{})
	c, k := pemPair(t, 7, time.Now().Add(time.Hour), "a.example")
	os.MkdirAll(m.certDir(), 0o700)
	os.WriteFile(filepath.Join(m.certDir(), "cert.pem"), c, 0o600)
	os.WriteFile(filepath.Join(m.certDir(), "key.pem"), k, 0o600)
	m2, _ := NewManager(o, Hooks{})
	if m2.Certificate() == nil || m2.Certificate().Leaf.SerialNumber.Int64() != 7 {
		t.Fatal("stored certificate not loaded")
	}
	// A stored certificate not covering every domain is ignored.
	o.Domains = []string{"a.example", "b.example"}
	m3, _ := NewManager(o, Hooks{})
	if m3.Certificate() != nil {
		t.Fatal("partial certificate used")
	}
}

func TestHTTPResponderShared(t *testing.T) {
	r1, e := acquireHTTP("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := r1.ln.Addr().String()
	r1.set("/.well-known/acme-challenge/tok", "tok.key")
	res, e := http.Get("http://" + addr + "/.well-known/acme-challenge/tok")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "tok.key" {
		t.Fatal(string(b))
	}
	res, _ = http.Get("http://" + addr + "/.well-known/acme-challenge/other")
	if res.StatusCode != 404 {
		t.Fatal(res.StatusCode)
	}
	res.Body.Close()
	r1.release()
	if _, e := http.Get("http://" + addr + "/"); e == nil {
		t.Fatal("responder still listening")
	}
}

func TestCloudflareProvider(t *testing.T) {
	var mu sync.Mutex
	records := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(403)
			w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.com" {
				w.Write([]byte(`{"success":true,"result":[{"id":"z1"}]}`))
			} else {
				w.Write([]byte(`{"success":true,"result":[]}`))
			}
		case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			records["r1"] = body["name"].(string) + "=" + body["content"].(string)
			w.Write([]byte(`{"success":true,"result":{"id":"r1"}}`))
		case r.Method == "DELETE" && r.URL.Path == "/zones/z1/dns_records/r1":
			delete(records, "r1")
			w.Write([]byte(`{"success":true,"result":{"id":"r1"}}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"not found"}]}`))
		}
	}))
	defer srv.Close()
	cf := &Cloudflare{Token: "tok", APIURL: srv.URL}
	id, e := cf.Present(context.Background(), "_acme-challenge.kat.example.com", "v1")
	if e != nil || id != "z1/r1" || records["r1"] != "_acme-challenge.kat.example.com=v1" {
		t.Fatal(id, e, records)
	}
	if e := cf.CleanUp(context.Background(), "", id); e != nil || len(records) != 0 {
		t.Fatal(e, records)
	}
	bad := &Cloudflare{Token: "wrong", APIURL: srv.URL}
	if _, e := bad.Present(context.Background(), "_acme-challenge.kat.example.com", "v"); e == nil || strings.Contains(e.Error(), "wrong") || !strings.Contains(e.Error(), "9109") {
		t.Fatal(e)
	}
}
