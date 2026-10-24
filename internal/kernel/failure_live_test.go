package kernel

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFailureRealDNSRouteDialAndBudget(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, nil, 1) })
	in := ssIn()
	in.Listen = "127.0.0.1:0"
	cfg := Config{Inbounds: []Inbound{in}, DNS: &DNSOptions{Server: "udp://" + f.udp.LocalAddr().String()}}
	if e := cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	cfg.Limits.DialTimeout = Duration(50 * time.Millisecond)
	var b bytes.Buffer
	s := &Server{cfg: cfg, ctx: context.Background(), dialSlots: make(chan struct{}, 1), failures: &failureLog{write: func(p []byte) error { _, e := b.Write(p); return e }}}
	var e error
	s.dns, e = newInternalDNS(cfg.DNS)
	if e != nil {
		t.Fatal(e)
	}
	defer s.dns.close()
	if c, e := s.dial(s.ctx, Address{"secret-target.example", 9}); e == nil {
		c.Close()
		t.Fatal("no-answer DNS accepted")
	}
	before := f.count.Load()
	s.cfg.Routing = &RoutingOptions{Rules: []RouteRule{{Domain: "secret-target.example", Action: "reject"}}}
	if c, e := s.dial(s.ctx, Address{"secret-target.example", 9}); e == nil {
		c.Close()
		t.Fatal("reject dialed")
	}
	if f.count.Load() != before {
		t.Fatal("domain reject queried")
	}
	s.cfg.Routing = nil
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	if c, e := s.dial(s.ctx, Address{"127.0.0.1", p}); e == nil {
		c.Close()
		t.Fatal("closed port dialed")
	}
	s.dialSlots <- struct{}{}
	_, e = s.dial(s.ctx, Address{"127.0.0.1", p})
	<-s.dialSlots
	if e == nil {
		t.Fatal("budget timeout missing")
	}
	for _, reason := range []string{"dns_failed", "rule_reject", "connect_failed", "budget_wait_timeout"} {
		if !strings.Contains(b.String(), reason) {
			t.Fatal("missing actual failure category", reason)
		}
	}
	for _, secret := range []string{"secret-target.example", "127.0.0.1"} {
		if strings.Contains(b.String(), secret) {
			t.Fatal("target leaked")
		}
	}
	t.Log("real isolated DNS/no-answer, pre-DNS rule reject, closed TCP dial, bounded quota wait: four distinct private reasons")
}
