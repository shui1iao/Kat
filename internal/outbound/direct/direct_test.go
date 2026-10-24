package direct_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/internal/proxytest"
)

func TestTCPResolveOrder(t *testing.T) {
	// Echo on 127.0.0.1; the resolver returns 127.0.0.3 first (nothing listens
	// there, connection refused), so the second candidate must be dialed.
	echo := proxytest.EchoTCP(t)
	var asked []string
	d := direct.New(direct.Options{Timeout: 3 * time.Second, Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		asked = append(asked, host)
		return []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("127.0.0.1")}, nil
	}})
	if d.Name() != "direct" || d.Type() != "direct" || !d.UDP() {
		t.Fatal("identity")
	}
	proxytest.TCPEcho(t, d, outbound.Addr{Host: "echo.test", Port: echo.Port}, 70000)
	if len(asked) != 1 || asked[0] != "echo.test" {
		t.Fatalf("resolver calls %v", asked)
	}
	// IP literals never call the resolver.
	proxytest.TCPEcho(t, d, echo, 10)
	if len(asked) != 1 {
		t.Fatalf("resolver called for IP literal: %v", asked)
	}
}

func TestTCPResolveError(t *testing.T) {
	want := errors.New("nxdomain")
	d := direct.New(direct.Options{Resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, want }})
	if _, e := d.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 1}); !errors.Is(e, want) {
		t.Fatalf("got %v", e)
	}
	if _, e := d.DialTCP(context.Background(), outbound.Addr{Host: "127.0.0.1", Port: 0}); e == nil {
		t.Fatal("zero port accepted")
	}
}

func TestUDPBothFamiliesAndDomain(t *testing.T) {
	d := direct.New(direct.Options{BindIPv4: netip.MustParseAddr("127.0.0.1"), Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}})
	e4 := proxytest.EchoUDP(t, "udp4")
	proxytest.UDPEcho(t, d, e4)
	proxytest.UDPEcho(t, d, outbound.Addr{Host: "echo.test", Port: e4.Port})
	if c, e := net.ListenPacket("udp6", "[::1]:0"); e == nil {
		c.Close()
		e6 := proxytest.EchoUDP(t, "udp6")
		pc, e := d.ListenPacket(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		defer pc.Close()
		// One PacketConn reaches both families.
		for _, dst := range []outbound.Addr{e4, e6} {
			if _, e = pc.WriteTo([]byte("x"), dst); e != nil {
				t.Fatal(e)
			}
			pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			b := make([]byte, 10)
			n, src, e := pc.ReadFrom(b)
			if e != nil || string(b[:n]) != "x" || src != dst {
				t.Fatalf("%v: %q %v %v", dst, b[:n], src, e)
			}
		}
	} else {
		t.Log("IPv6 loopback unavailable; dual-family part skipped:", e)
	}
}

// Only datagrams from an exact IP:port previously sent to are delivered.
func TestUDPRejectsUnsolicitedSource(t *testing.T) {
	d := direct.New(direct.Options{BindIPv4: netip.MustParseAddr("127.0.0.1")})
	pc, e := d.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	peer, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	stranger, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer stranger.Close()
	pa := peer.LocalAddr().(*net.UDPAddr)
	if _, e = pc.WriteTo([]byte("hello"), outbound.Addr{Host: "127.0.0.1", Port: uint16(pa.Port)}); e != nil {
		t.Fatal(e)
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 100)
	_, local, e := peer.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	// Same IP, different port: must be dropped.
	stranger.WriteToUDP([]byte("spoof"), local)
	pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, src, e := pc.ReadFrom(b); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("unsolicited datagram delivered: %q from %v (%v)", b[:n], src, e)
	}
	// The real peer still gets through.
	peer.WriteToUDP([]byte("reply"), local)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, src, e := pc.ReadFrom(b)
	if e != nil || string(b[:n]) != "reply" || src.Port != uint16(pa.Port) {
		t.Fatalf("%q %v %v", b[:n], src, e)
	}
	// Close unblocks a pending read.
	pc.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, _, e := pc.ReadFrom(b); done <- e }()
	time.Sleep(50 * time.Millisecond)
	pc.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read after close succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}

func TestDialTimeout(t *testing.T) {
	d := direct.New(direct.Options{Timeout: 200 * time.Millisecond, Resolve: func(ctx context.Context, string string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	start := time.Now()
	if _, e := d.DialTCP(context.Background(), outbound.Addr{Host: "slow.test", Port: 80}); e == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not applied")
	}
}
