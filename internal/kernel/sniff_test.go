package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/route"
)

// tlsHello returns the first flight of a crypto/tls client for sni.
func tlsHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go tls.Client(a, &tls.Config{ServerName: sni}).Handshake()
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, e := io.ReadFull(b, hdr); e != nil {
		t.Fatal(e)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, e := io.ReadFull(b, body); e != nil {
		t.Fatal(e)
	}
	return append(hdr, body...)
}

// sendFirst opens a SOCKS5 stream to dst, writes first and reports whether
// the echo came back (false: the connection was refused or closed).
func sendFirst(t *testing.T, client outbound.Dialer, dst outbound.Addr, first []byte) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := client.DialTCP(ctx, dst)
	if e != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e := c.Write(first); e != nil {
		return false
	}
	got := make([]byte, len(first))
	if _, e := io.ReadFull(c, got); e != nil {
		return false
	}
	return bytes.Equal(got, first)
}

func socksClient(t *testing.T, s *Server) outbound.Outbound {
	t.Helper()
	c, e := socks5.New(outbound.Options{Name: "c", Type: "socks5", Server: "127.0.0.1", Port: uint16(s.Addresses()[0].(*net.TCPAddr).Port)}, direct.New(direct.Options{}))
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func ruleHits(s *Server, prefix string) uint64 {
	for _, r := range s.StatsView().Cumulative.Rules {
		if strings.HasPrefix(r.Name, prefix) {
			return r.Hits
		}
	}
	return 0
}

func TestSniffTCPRulesAndProtocol(t *testing.T) {
	echo := rcEchoTCP(t)
	port := strconv.Itoa(int(echo))
	rules := []RouteRule{
		{DomainSuffix: "tls-reject.test", Action: "reject"},
		{RouteRuleExt: RouteRuleExt{And: []route.Rule{{Protocol: "http"}, {DomainSuffix: "http-reject.test"}}}, Action: "reject"},
		{RouteRuleExt: RouteRuleExt{Protocol: "tls"}, Action: "direct"},
		{RouteRuleExt: RouteRuleExt{InName: "edge"}, Action: "direct"},
	}
	start := func(enabled bool) *Server {
		return startTest(t, Inbound{Protocol: "socks5", Name: "edge", Sniff: &SniffOptions{Enabled: enabled, TCPPorts: port}}, func(c *Config) {
			c.Routing = &RoutingOptions{Rules: rules}
		})
	}
	s := start(true)
	client := socksClient(t, s)
	dst := outbound.Addr{Host: "127.0.0.1", Port: echo}
	for _, c := range []struct {
		name  string
		first []byte
		ok    bool
	}{
		{"tls sni rejected by domain rule", tlsHello(t, "a.tls-reject.test"), false},
		{"tls other sni", tlsHello(t, "ok.test"), true},
		{"http host rejected by and(protocol,domain)", []byte("GET / HTTP/1.1\r\nHost: x.http-reject.test\r\n\r\n"), false},
		{"http other host", []byte("GET / HTTP/1.1\r\nHost: fine.test\r\n\r\n"), true},
		{"tls-reject host but plain bytes", []byte("hello a.tls-reject.test"), true},
	} {
		if got := sendFirst(t, client, dst, c.first); got != c.ok {
			t.Fatalf("%s: echoed=%v", c.name, got)
		}
	}
	if h := ruleHits(s, "domain_suffix:tls-reject.test"); h != 1 {
		t.Fatal("tls-reject hits", h, s.StatsView().Cumulative.Rules)
	}
	if h := ruleHits(s, "and("); h != 1 {
		t.Fatal("and hits", h, s.StatsView().Cumulative.Rules)
	}
	if h := ruleHits(s, "protocol:tls"); h != 1 {
		t.Fatal("protocol hits", h, s.StatsView().Cumulative.Rules)
	}
	if h := ruleHits(s, "in_name:edge"); h != 2 {
		t.Fatal("in_name hits", h, s.StatsView().Cumulative.Rules)
	}
	// Sniffing disabled (the default): the domain is never learned.
	s2 := start(false)
	if !sendFirst(t, socksClient(t, s2), dst, tlsHello(t, "a.tls-reject.test")) {
		t.Fatal("sniffing off still rejected")
	}
	// Port not listed: no sniffing.
	s3 := startTest(t, Inbound{Protocol: "socks5", Sniff: &SniffOptions{Enabled: true, TCPPorts: "1-2"}}, func(c *Config) {
		c.Routing = &RoutingOptions{Rules: rules[:1]}
	})
	if !sendFirst(t, socksClient(t, s3), dst, tlsHello(t, "a.tls-reject.test")) {
		t.Fatal("unlisted port sniffed")
	}
}

func TestSniffOverrideDestination(t *testing.T) {
	echo := rcEchoTCP(t)
	dns := rcDNS(t) // *.test -> 127.0.0.1
	mk := func(override bool) *Server {
		return startTest(t, Inbound{Protocol: "socks5", Sniff: &SniffOptions{Enabled: true, TCPPorts: strconv.Itoa(int(echo)), OverrideDestination: override}}, func(c *Config) {
			c.DNS = &DNSOptions{Server: "udp://" + dns.udp.LocalAddr().String()}
		})
	}
	// 127.0.0.2 has no listener: only a dial to the sniffed name's address works.
	dst := outbound.Addr{Host: "127.0.0.2", Port: echo}
	if sendFirst(t, socksClient(t, mk(false)), dst, tlsHello(t, "x.sniff.test")) {
		t.Fatal("without override the IP target was not used")
	}
	s := mk(true)
	if !sendFirst(t, socksClient(t, s), dst, tlsHello(t, "x.sniff.test")) {
		t.Fatal("override did not dial the resolved sniffed name")
	}
	// No SNI: the original target is kept.
	if sendFirst(t, socksClient(t, s), dst, []byte("plain")) {
		t.Fatal("override without a sniffed name changed the target")
	}
}

// bannerServer writes a banner immediately (server-first protocol).
func bannerServer(t *testing.T) uint16 {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
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
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func bannerDelay(t *testing.T, client outbound.Dialer, port uint16) time.Duration {
	t.Helper()
	start := time.Now()
	c, e := client.DialTCP(context.Background(), outbound.Addr{Host: "127.0.0.1", Port: port})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 8)
	if _, e := io.ReadFull(c, b); e != nil || string(b) != "SSH-2.0-" {
		t.Fatal(e, b)
	}
	return time.Since(start)
}

func TestSniffNoWaitOffPortsAndBoundedWait(t *testing.T) {
	banner := bannerServer(t)
	rules := &RoutingOptions{Rules: []RouteRule{{RouteRuleExt: RouteRuleExt{Protocol: "tls"}, Action: "reject"}}}
	off := startTest(t, Inbound{Protocol: "socks5", Sniff: &SniffOptions{Enabled: true}}, func(c *Config) { c.Routing = rules })
	var worst time.Duration
	for i := 0; i < 5; i++ {
		worst = max(worst, bannerDelay(t, socksClient(t, off), banner))
	}
	if worst > 100*time.Millisecond {
		t.Fatal("server-first protocol on a non-sniffed port waited", worst)
	}
	on := startTest(t, Inbound{Protocol: "socks5", Sniff: &SniffOptions{Enabled: true, TCPPorts: strconv.Itoa(int(banner)), Timeout: Duration(200 * time.Millisecond)}}, func(c *Config) { c.Routing = rules })
	d := bannerDelay(t, socksClient(t, on), banner)
	if d < 180*time.Millisecond || d > time.Second {
		t.Fatal("sniffed port wait is not the configured bound", d)
	}
	t.Logf("non-sniffed port worst %v; sniffed port with server-first protocol %v (timeout 200ms)", worst, d)
}

// ---- QUIC ----

func appendQV(b []byte, v uint64) []byte {
	if v < 64 {
		return append(b, byte(v))
	}
	return append(b, 0x40|byte(v>>8), byte(v))
}

func quicLabel(secret []byte, label string, n int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, byte(6+len(label)))
	info = append(info, "tls13 "+label...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), n)
	return out
}

// quicInitial builds a QUIC v1 client Initial carrying a real ClientHello.
func quicInitial(t *testing.T, sni string) []byte {
	t.Helper()
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	q.SetTransportParameters(nil)
	if e := q.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	var ch []byte
	for ch == nil {
		ev := q.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			t.Fatal("no ClientHello")
		}
		if ev.Kind == tls.QUICWriteData {
			ch = append([]byte(nil), ev.Data...)
		}
	}
	frames := appendQV(appendQV([]byte{0x06}, 0), uint64(len(ch)))
	frames = append(frames, ch...)
	for len(frames) < 1150 {
		frames = append(frames, 0)
	}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initial, _ := hkdf.Extract(sha256.New, dcid, salt)
	client := quicLabel(initial, "client in", 32)
	key, iv, hp := quicLabel(client, "quic key", 16), quicLabel(client, "quic iv", 12), quicLabel(client, "quic hp", 16)
	hdr := []byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // scid len 0, token len 0
	length := 4 + len(frames) + 16
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOff := len(hdr)
	hdr = append(hdr, 0, 0, 0, 0)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	pkt := append(hdr, aead.Seal(nil, iv, frames, hdr)...)
	hb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hb.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func udpRoundTrip(pc outbound.PacketConn, dst outbound.Addr, p []byte) bool {
	b := make([]byte, 65535)
	for range 3 {
		if _, e := pc.WriteTo(p, dst); e != nil {
			return false
		}
		pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _, e := pc.ReadFrom(b)
		if e == nil && bytes.Equal(b[:n], p) {
			return true
		}
	}
	return false
}

func TestSniffQUIC(t *testing.T) {
	uecho := rcEchoUDP(t)
	s := startTest(t, Inbound{Protocol: "socks5", Sniff: &SniffOptions{Enabled: true, UDPPorts: strconv.Itoa(int(uecho))}}, func(c *Config) {
		c.Routing = &RoutingOptions{Rules: []RouteRule{
			{RouteRuleExt: RouteRuleExt{And: []route.Rule{{Protocol: "quic"}, {DomainSuffix: "q-reject.test"}}}, Action: "reject"},
		}}
	})
	client := socksClient(t, s)
	open := func() outbound.PacketConn {
		pc, e := client.ListenPacket(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { pc.Close() })
		return pc
	}
	dst := outbound.Addr{Host: "127.0.0.1", Port: uecho}
	if udpRoundTrip(open(), dst, quicInitial(t, "a.q-reject.test")) {
		t.Fatal("QUIC SNI not used by the rule")
	}
	if !udpRoundTrip(open(), dst, quicInitial(t, "ok.test")) {
		t.Fatal("QUIC with another SNI dropped")
	}
	start := time.Now()
	if !udpRoundTrip(open(), dst, []byte("plain datagram")) {
		t.Fatal("non-QUIC datagram dropped")
	}
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatal("non-QUIC datagram waited", d)
	}
	if ruleHits(s, "and(") == 0 {
		t.Fatal("no rule hit", s.StatsView().Cumulative.Rules)
	}
}

func TestSniffConfigValidation(t *testing.T) {
	for _, o := range []SniffOptions{
		{Enabled: true, TCPPorts: "0"},
		{Enabled: true, UDPPorts: "1-"},
		{Enabled: true, Timeout: Duration(3 * time.Second)},
	} {
		c := Config{Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0", Sniff: &o}}}
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	o := SniffOptions{Enabled: true}
	if e := o.normalize(); e != nil || o.TCPPorts != "80,443,8080,8443" || o.UDPPorts != "443" || o.Timeout.value() != 300*time.Millisecond {
		t.Fatal(o, e)
	}
	if !o.tcp.Contains(8443) || o.tcp.Contains(22) || !o.udp.Contains(443) || o.udp.Contains(80) {
		t.Fatal("defaults")
	}
	o = SniffOptions{Enabled: true, TCPPorts: "none"}
	if o.normalize() != nil || len(o.tcp) != 0 {
		t.Fatal("none")
	}
	// in_name must name an inbound.
	c := Config{Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0", Name: "a"}}, Routing: &RoutingOptions{Rules: []RouteRule{{RouteRuleExt: RouteRuleExt{InName: "b"}, Action: "reject"}}}}
	if c.Validate() == nil {
		t.Fatal("unknown in_name accepted")
	}
	c.Routing.Rules[0].InName = "a"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	dup := Config{Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0", Name: "a"}, {Protocol: "socks5", Listen: "127.0.0.1:0", Name: "a"}}}
	if dup.Validate() == nil {
		t.Fatal("duplicate inbound name accepted")
	}
}

func TestRouteRuleJSONNewFields(t *testing.T) {
	ok := `{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0","name":"in1","sniff":{"enabled":true,"tcp_ports":"443,8443","udp_ports":"443","timeout":"250ms","override_destination":true}}],
	"routing":{"rules":[
	 {"and":[{"domain_suffix":"a.example"},{"not":{"dst_port":"80"}}],"action":"reject"},
	 {"or":[{"domain_regex":"^x[0-9]+\\.example$"},{"domain_wildcard":"*.w.example"}],"action":"direct"},
	 {"ip_suffix":"0.0.0.1/8","action":"direct"},
	 {"src_port":"1000-2000","action":"direct"},
	 {"in_port":"1080","action":"direct"},
	 {"in_name":"in1","action":"direct"},
	 {"in_type":"socks5","action":"direct"},
	 {"protocol":"quic","action":"reject"},
	 {"dst_port":"80,443,1000-2000","action":"direct"}
	]}}`
	if e := loadJSON(t, ok); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"routing":{"rules":[{"and":[{"domain":"a.example","action":"reject"},{"network":"tcp"}],"action":"reject"}]}}`,
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"routing":{"rules":[{"and":null,"action":"reject"}]}}`,
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"routing":{"rules":[{"process_name":"curl","action":"reject"}]}}`,
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"routing":{"rules":[{"geosite":"google","action":"reject"}]}}`,
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"routing":{"rules":[{"ip_asn":"13335","action":"reject"}]}}`,
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"routing":{"rules":[{"protocol":"ssh","action":"reject"}]}}`,
		`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0","sniff":{"enabled":true,"ports":"443"}}]}`,
	} {
		if loadJSON(t, bad) == nil {
			t.Fatal("accepted", bad)
		}
	}
}

// Geosite and ASN events keep their names and fields; their update failures
// are warnings counted as rule-data failures like rule sets and GeoIP.
func TestRouteDataEvents(t *testing.T) {
	var b bytes.Buffer
	l := &eventLog{write: func(p []byte) error { _, e := b.Write(p); return e }}
	now := time.Unix(100, 0)
	l.emit(now, "geosite_update_failed", "class", "parse")
	l.emit(now, "asn_update_failed", "class", "status")
	l.emit(now, "geosite_loaded", "categories", "3", "missing", "0")
	l.emit(now, "asn_loaded")
	l.emit(now, "geosite_category_missing", "category", "nope")
	want := "kat event=geosite_update_failed class=parse suppressed=0\nkat event=asn_update_failed class=status suppressed=0\n" +
		"kat event=geosite_loaded categories=3 missing=0 suppressed=0\nkat event=asn_loaded suppressed=0\n" +
		"kat event=geosite_category_missing category=nope suppressed=0\n"
	if b.String() != want {
		t.Fatal(b.String())
	}
	if eventLevelOf("geosite_update_failed") != levelWarn || eventLevelOf("asn_update_failed") != levelWarn {
		t.Fatal("update failures must be warnings")
	}
}

// An AnyTLS stream opened after a reload on a session accepted earlier is
// routed by the current generation, with the current inbound attributes
// (name, sniffing) of its listener.
func TestAnyTLSStreamUsesCurrentInboundAttributes(t *testing.T) {
	cert, pool := testCert(t)
	target := echoTCP(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	in.Name = "old"
	c0 := socksCfg()
	// in_name must name a configured inbound: "new" is a SOCKS5 inbound first.
	c0.Inbounds = []Inbound{in, {Protocol: "socks5", Listen: reloadPort(t), Name: "new"}}
	c0.Routing = &RoutingOptions{Rules: []RouteRule{{RouteRuleExt: RouteRuleExt{InName: "new"}, Action: "reject"}}}
	next := c0
	s := startReloadable(t, c0, &next)
	c := atBegin(t, s, pool, 2, in.Listen)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	p := []byte("before")
	atOpen(t, c, 1, target, p)
	if got := atPayload(t, c, 1, len(p)); string(got) != string(p) {
		t.Fatal("stream 1")
	}
	writeAll(c, atFrame(3, 1, nil))
	n := c0
	n.Inbounds = []Inbound{in}
	n.Inbounds[0].Name = "new"
	next = n
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	atOpen(t, c, 2, target, []byte("after"))
	waitFor(t, func() bool {
		for _, r := range s.StatsView().Cumulative.Rules {
			if r.Name == "in_name:new->reject" && r.Hits == 1 {
				return true
			}
		}
		return false
	})
}
