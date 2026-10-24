package kernel

// Real-process E2E for an AnyTLS inbound without "tls" (ephemeral in-memory
// certificate). Same gating as routing_e2e_test.go (KAT_E2E_KAT,
// KAT_INTEROP_SINGBOX). Runs that start real processes should not overlap.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func (w *e2eWorld) servedCert(port int) *x509.Certificate {
	w.t.Helper()
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true})
	if e != nil {
		w.t.Fatalf("TLS probe: %v", e)
	}
	defer c.Close()
	st := c.ConnectionState()
	if len(st.PeerCertificates) != 1 {
		w.t.Fatalf("peer chain length %d", len(st.PeerCertificates))
	}
	return st.PeerCertificates[0]
}

func certPin(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

func TestE2EAnyTLSEphemeralCert(t *testing.T) {
	w := e2eSetup(t)
	up := w.katUpstream("kat-anytls-ephemeral", map[string]any{"protocol": "anytls", "anytls": map[string]any{"password": e2eAnyTLSPass}})
	if out, e := exec.Command(w.kat, "check", up.cfgPath).CombinedOutput(); e != nil || !strings.Contains(string(out), "configuration valid") {
		t.Fatalf("kat check on tls-less AnyTLS config: %v %s", e, out)
	}
	w.logf("OK kat check %s: configuration valid", up.cfgPath)

	c1 := w.servedCert(up.port)
	pub, ok := c1.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || c1.Subject.CommonName != "localhost" || len(c1.IPAddresses) != 0 {
		t.Fatalf("unexpected served certificate: %T %v %v", c1.PublicKey, c1.Subject, c1.IPAddresses)
	}
	if d := time.Until(c1.NotAfter); d < 3650*24*time.Hour-time.Hour || d > 3653*24*time.Hour {
		t.Fatalf("NotAfter %v", c1.NotAfter)
	}
	pin1 := certPin(c1)
	if pin1 == w.pin {
		t.Fatal("served the fixture certificate")
	}
	w.logf("EVIDENCE served certificate #1: sha256=%s serial=%s CN=%s DNS=%v notBefore=%s notAfter=%s key=ECDSA-P256",
		pin1, c1.SerialNumber.Text(16), c1.Subject.CommonName, c1.DNSNames, c1.NotBefore.UTC().Format(time.RFC3339), c1.NotAfter.UTC().Format(time.RFC3339))

	f := w.forwarder("anytls_eph", up.port, 0)
	all := []*e2eFwd{f}
	p, c := w.entry(map[string]any{
		"dns": map[string]any{"server": w.dnsServer()},
		"outbounds": []any{
			map[string]any{"name": "eph_insecure", "type": "anytls", "server": "127.0.0.1", "port": f.port, "password": e2eAnyTLSPass, "tls": map[string]any{"insecure": true}},
			map[string]any{"name": "eph_wrong_pin", "type": "anytls", "server": "127.0.0.1", "port": f.port, "password": e2eAnyTLSPass, "tls": map[string]any{"pin_sha256": w.pin}},
			map[string]any{"name": "eph_verify", "type": "anytls", "server": "127.0.0.1", "port": f.port, "password": e2eAnyTLSPass, "tls": map[string]any{"server_name": "localhost"}},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"domain_suffix": "eph.e2e.test", "outbound": "eph_insecure"},
			map[string]any{"domain_suffix": "pin.e2e.test", "outbound": "eph_wrong_pin"},
			map[string]any{"domain_suffix": "verify.e2e.test", "outbound": "eph_verify"},
		}},
	})
	e1 := w.echoTCP["127.0.0.1"]
	clients := []struct {
		n string
		d outbound.Dialer
	}{{"socks5", c.socks}, {"ss2022", c.ss}}

	s := snapshot(all...)
	w.must("socks5 TCP a.eph.e2e.test (anytls insecure, ephemeral cert)", e2eTCP(c.socks, "a.eph.e2e.test", e1))
	w.expect("TCP through ephemeral-cert AnyTLS", delta(s, all...), map[string][2]int64{"anytls_eph": {1, 0}})
	w.must("ss2022 TCP b.eph.e2e.test (anytls insecure, ephemeral cert)", e2eTCP(c.ss, "b.eph.e2e.test", e1))
	for _, cl := range clients {
		s = snapshot(all...)
		w.must(cl.n+" UDP u.eph.e2e.test (UoT over ephemeral-cert AnyTLS)", e2eUDP(cl.d, "u.eph.e2e.test", w.echoUDP, 3))
		if d := delta(s, all...); d["anytls_eph"][1] != 0 || f.tcp.Load() < 1 {
			t.Fatalf("UDP was not carried over the AnyTLS TCP session: %v", d)
		}
	}
	w.logf("EVIDENCE anytls_eph forwarder totals tcp_conns=%d udp_datagrams=%d (UDP carried as UoT inside TLS)", f.tcp.Load(), f.udp.Load())

	for _, x := range []struct{ host, what string }{{"a.pin.e2e.test", "wrong pin"}, {"a.verify.e2e.test", "default verification"}} {
		s = snapshot(all...)
		if e := e2eTCP(c.socks, x.host, e1); e == nil {
			t.Fatalf("%s accepted the ephemeral certificate", x.what)
		} else {
			w.logf("EVIDENCE %s rejected: %v (forwarder delta %v)", x.what, e, delta(s, all...))
		}
		if e := e2eUDP(c.socks, "u."+strings.TrimPrefix(x.host, "a."), w.echoUDP, 2); e == nil {
			t.Fatalf("%s UDP accepted the ephemeral certificate", x.what)
		}
	}

	// A restart generates a new certificate; pinning the old one is useless.
	if e := up.term(10 * time.Second); e != nil {
		t.Fatalf("upstream SIGTERM: %v", e)
	}
	up.start()
	c2 := w.servedCert(up.port)
	pin2 := certPin(c2)
	if pin2 == pin1 || c2.SerialNumber.Cmp(c1.SerialNumber) == 0 {
		t.Fatal("restart served the same certificate")
	}
	w.logf("EVIDENCE served certificate #2 after restart: sha256=%s serial=%s (differs from #1)", pin2, c2.SerialNumber.Text(16))
	var e error
	for i := 0; i < 3; i++ { // an idle session to the old process may be handed out once
		if e = e2eTCP(c.socks, "r.eph.e2e.test", e1); e == nil {
			break
		}
		w.logf("after restart attempt %d: %v", i+1, e)
		time.Sleep(200 * time.Millisecond)
	}
	w.must("socks5 TCP after upstream restart (new ephemeral cert, insecure)", e)
	w.must("socks5 UDP after upstream restart", e2eUDP(c.socks, "r.eph.e2e.test", w.echoUDP, 3))
	w.stopEntry(p)
	if e := up.term(10 * time.Second); e != nil {
		t.Fatalf("upstream SIGTERM: %v", e)
	}
}
