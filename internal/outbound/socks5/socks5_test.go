package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/internal/proxytest"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
)

func opts(port int, user, pass string) outbound.Options {
	return outbound.Options{Name: "s5", Type: "socks5", Server: "127.0.0.1", Port: uint16(port), Username: user, Password: pass}
}

func TestValidate(t *testing.T) {
	f := false
	good := []outbound.Options{
		opts(1080, "", ""),
		opts(1080, "u", "p"),
		{Name: "a", Type: "socks5", Server: "Proxy.Example.com", Port: 65535, UDP: &f, Via: "hk"},
		{Name: "a", Type: "socks5", Server: "::1", Port: 1},
	}
	for i, o := range good {
		if e := socks5.Validate(o); e != nil {
			t.Errorf("good %d: %v", i, e)
		}
	}
	bad := []outbound.Options{
		{Name: "a", Type: "socks", Server: "1.2.3.4", Port: 1},
		{Type: "socks5", Server: "1.2.3.4", Port: 1},
		{Name: "a", Type: "socks5", Server: "", Port: 1},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 0},
		{Name: "a", Type: "socks5", Server: "fe80::1%eth0", Port: 1},
		{Name: "a", Type: "socks5", Server: "bad host", Port: 1},
		{Name: "a", Type: "socks5", Server: "-x.com", Port: 1},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, Username: "u"},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, Password: "p"},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, Username: strings.Repeat("u", 256), Password: "p"},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, Method: "aes-128-gcm"},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, Key: "x"},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, TLS: &outbound.TLSOptions{}},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, IdleSessions: 1},
		{Name: "a", Type: "socks5", Server: "1.2.3.4", Port: 1, IdleTimeout: 1},
	}
	for i, o := range bad {
		if e := socks5.Validate(o); e == nil {
			t.Errorf("bad %d accepted: %+v", i, o)
		}
		if _, e := socks5.New(o, direct.New(direct.Options{})); e == nil {
			t.Errorf("bad %d: New accepted", i)
		}
	}
	if _, e := socks5.New(opts(1, "", ""), nil); e == nil {
		t.Error("nil under accepted")
	}
}

func TestUDPCapability(t *testing.T) {
	f := false
	o := opts(1, "", "")
	s, _ := socks5.New(o, direct.New(direct.Options{}))
	if !s.UDP() || s.Name() != "s5" || s.Type() != "socks5" {
		t.Fatal("default udp/identity")
	}
	o.UDP = &f
	s, _ = socks5.New(o, direct.New(direct.Options{}))
	if s.UDP() {
		t.Fatal("udp:false ignored")
	}
	if _, e := s.ListenPacket(context.Background()); !errors.Is(e, outbound.ErrUDPUnsupported) {
		t.Fatal(e)
	}
	s, _ = socks5.New(opts(1, "", ""), proxytest.TCPOnly{Under: direct.New(direct.Options{})})
	if s.UDP() {
		t.Fatal("UDP() ignores under.UDP()")
	}
	if _, e := s.ListenPacket(context.Background()); !errors.Is(e, outbound.ErrUDPUnsupported) {
		t.Fatal(e)
	}
}

// fakeServer is a minimal UDP-ASSOCIATE-only server: it replies with an
// unspecified BND address and closes the control connection on demand.
func TestAssociateLifecycle(t *testing.T) {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	relay, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	rport := relay.LocalAddr().(*net.UDPAddr).Port
	closeCtrl := make(chan struct{})
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 3)
		io.ReadFull(c, b)
		c.Write([]byte{5, 0})
		req := make([]byte, 10)
		io.ReadFull(c, req)
		// BND = 0.0.0.0:rport -> client must use the server address.
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, byte(rport >> 8), byte(rport)})
		<-closeCtrl
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := relay.ReadFromUDP(b)
			if e != nil {
				return
			}
			relay.WriteToUDP(b[:n], a) // reflect header+payload unchanged
		}
	}()
	s, _ := socks5.New(opts(ln.Addr().(*net.TCPAddr).Port, "", ""), direct.New(direct.Options{}))
	pc, e := s.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	dst := outbound.Addr{Host: "example.com", Port: 53}
	if _, e = pc.WriteTo([]byte("ping"), dst); e != nil {
		t.Fatal(e)
	}
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 100)
	n, src, e := pc.ReadFrom(b)
	if e != nil || string(b[:n]) != "ping" || src != dst {
		t.Fatalf("%q %v %v", b[:n], src, e)
	}
	pc.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, _, e := pc.ReadFrom(b); done <- e }()
	close(closeCtrl)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read succeeded after control close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("control connection close did not close the PacketConn")
	}
}

func singBoxSocks(t *testing.T, user, pass string) int {
	in := map[string]any{"type": "socks"}
	if user != "" {
		in["users"] = []any{map[string]any{"username": user, "password": pass}}
	}
	return proxytest.StartSingBox(t, in)
}

func katSocks(t *testing.T, user, pass string) int {
	in := map[string]any{"protocol": "socks5"}
	if user != "" {
		in["users"] = []any{map[string]any{"username": user, "password": pass}}
	}
	return proxytest.StartKat(t, in)
}

func TestInterop(t *testing.T) {
	for _, srv := range []struct {
		name  string
		start func(*testing.T, string, string) int
	}{{"singbox", singBoxSocks}, {"kat", katSocks}} {
		for _, auth := range []struct{ user, pass string }{{"", ""}, {"alice", "s3cret-pass"}} {
			name := srv.name + "/noauth"
			if auth.user != "" {
				name = srv.name + "/userpass"
			}
			t.Run(name, func(t *testing.T) {
				port := srv.start(t, auth.user, auth.pass)
				s, e := socks5.New(opts(port, auth.user, auth.pass), direct.New(direct.Options{}))
				if e != nil {
					t.Fatal(e)
				}
				proxytest.TCPEcho(t, s, proxytest.EchoTCP(t), 100000)
				proxytest.UDPEcho(t, s, proxytest.EchoUDP(t, "udp4"))
				t.Logf("PASS %s socks5 TCP echo + UDP echo", name)
				if auth.user != "" {
					bad, _ := socks5.New(opts(port, auth.user, "wrong"), direct.New(direct.Options{}))
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if c, e := bad.DialTCP(ctx, proxytest.EchoTCP(t)); e == nil {
						c.Close()
						t.Fatal("wrong password accepted")
					} else {
						t.Logf("wrong password rejected: %v", e)
					}
				}
			})
		}
	}
}

// A server that accepts and never answers: the handshake is bounded by ctx.
func TestHandshakeBoundedByContext(t *testing.T) {
	s, _ := socks5.New(opts(proxytest.Blackhole(t), "u", "p"), direct.New(direct.Options{}))
	for _, op := range []string{"tcp", "udp"} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		var e error
		if op == "tcp" {
			var c net.Conn
			if c, e = s.DialTCP(ctx, outbound.Addr{Host: "example.com", Port: 80}); c != nil {
				c.Close()
			}
		} else {
			var pc outbound.PacketConn
			if pc, e = s.ListenPacket(ctx); pc != nil {
				pc.Close()
			}
		}
		cancel()
		if e == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("%s: err=%v after %v", op, e, time.Since(start))
		}
		t.Logf("%s against silent server: %v after %v", op, e, time.Since(start).Round(time.Millisecond))
	}
}
