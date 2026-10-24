package kernel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSRoutingCNAMEExpiryAndUnrelatedAnswers(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte {
		b := dnsReply(w, []string{"127.0.0.1"}, 100)
		var m dnsmessage.Message
		m.Unpack(b)
		q := m.Questions[0]
		alias, _ := dnsmessage.NewName("canonical.example.")
		for i := range m.Answers {
			m.Answers[i].Header.Name = alias
		}
		cn := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeCNAME, TTL: 1}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}
		other, _ := dnsmessage.NewName("unrelated.example.")
		m.Answers = append(m.Answers, cn, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: other, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 99}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}})
		b, _ = m.Pack()
		return b
	})
	r := configuredDNS(t, f.address(), 2)
	a, e := lookupDNS(t, r, "alias.example")
	if e != nil || len(a) != 1 || a[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("CNAME answer ownership", a, e)
	}
	before := f.count.Load()
	if _, e = lookupDNS(t, r, "alias.example"); e != nil || f.count.Load() != before {
		t.Fatal("CNAME positive cache")
	}
	time.Sleep(1050 * time.Millisecond)
	if _, e = lookupDNS(t, r, "alias.example"); e != nil || f.count.Load() != before+2 {
		t.Fatal("authoritative CNAME TTL not applied", e, f.count.Load())
	}
}

func TestDNSRoutingDeniedCandidateNetworkCounters(t *testing.T) {
	var deniedTCP atomic.Int64
	allowed := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { io.Copy(c, c) })
	sinkTCP(t, "tcp4", net.JoinHostPort("127.0.0.2", itoaPort(allowed.Port)), func(c net.Conn) { deniedTCP.Add(1) })
	target := localUDP(t)
	blocked, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: target.LocalAddr().(*net.UDPAddr).Port})
	if e != nil {
		t.Fatal(e)
	}
	defer blocked.Close()
	f := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.2", "127.0.0.1"}, 30) })
	s := startTest(t, ssIn(), func(c *Config) {
		c.DNS = &DNSOptions{Server: f.address()}
		c.Routing = &RoutingOptions{Rules: []RouteRule{{IPCIDR: "127.0.0.2/32", Action: "reject"}}}
	})
	c, e := s.dial(context.Background(), Address{"multi.example", allowed.Port})
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	client := localUDP(t)
	client.WriteToUDP(udp2022(t, Address{"multi.example", addrFromNet(target.LocalAddr()).Port}, 950, 1, []byte("allow")), endpoint)
	recvUDP(t, target)
	silentUDP(t, blocked)
	if deniedTCP.Load() != 0 {
		t.Fatal("denied IP accepted TCP", deniedTCP.Load())
	}
	t.Logf("multi-IP rejected TCP accepts=%d, rejected UDP receives=0; literal allowed address used", deniedTCP.Load())
}
func itoaPort(p uint16) string { return strconv.Itoa(int(p)) }

func TestDNSRoutingActualSystemBootstrapLocalhost(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 10) })
	// Cover both addresses returned by the real system localhost resolver, no public DNS.
	v6, e := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: f.udp.LocalAddr().(*net.UDPAddr).Port})
	if e != nil {
		t.Skipf("IPv6 local bootstrap unavailable: %v", e)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, p, e := v6.ReadFromUDP(b)
			if e != nil {
				return
			}
			v6.WriteToUDP(dnsReply(b[:n], []string{"127.0.0.1"}, 10), p)
		}
	}()
	defer func() { v6.Close(); wg.Wait() }()
	r := configuredDNS(t, "localhost:"+itoaPort(uint16(f.tcp.Addr().(*net.TCPAddr).Port)), 0)
	if _, e = lookupDNS(t, r, "bootstrap-target.example"); e != nil {
		t.Fatal("real system bootstrap for upstream hostname failed", e)
	}
}

func TestDNSRoutingDoHCloseAndCancellation(t *testing.T) {
	var open atomic.Int64
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsReply(b, []string{"127.0.0.1"}, 1))
	}))
	h.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			open.Add(1)
		}
		if s == http.StateClosed {
			open.Add(-1)
		}
	}
	h.StartTLS()
	defer h.Close()
	r := configuredDNS(t, h.URL+"/dns-query", 0)
	pool := x509.NewCertPool()
	pool.AddCert(h.Certificate())
	r.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if _, e := lookupDNS(t, r, "close.example"); e != nil {
		t.Fatal(e)
	}
	r.close()
	waitFor(t, func() bool { return open.Load() == 0 })
	stuck := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(300 * time.Millisecond):
		}
	}))
	defer stuck.Close()
	d := configuredDNS(t, stuck.URL+"/dns-query", 0)
	roots := x509.NewCertPool()
	roots.AddCert(stuck.Certificate())
	d.transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithCancel(context.Background())
	ctx, timeout := context.WithTimeout(ctx, time.Second)
	defer timeout()
	done := make(chan error, 1)
	go func() { _, e := d.lookup(ctx, "cancel.example"); done <- e }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("DoH cancellation ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("DoH cancellation stuck")
	}
	d.close()
}

func TestDNSRoutingBroadIPv6PrefixValidation(t *testing.T) {
	c := Config{Routing: &RoutingOptions{Rules: []RouteRule{{IPCIDR: "::ffff:192.0.2.1/80", Action: "reject"}}}}
	if e := c.validateNetwork(); e != nil {
		t.Fatal("valid broad IPv6 prefix rejected", e)
	}
	s := &Server{cfg: c}
	if !s.routeDirect("", netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("broad IPv6 prefix accidentally expanded to IPv4")
	}
}
