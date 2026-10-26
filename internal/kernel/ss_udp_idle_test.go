package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/sha1"
	SS "github.com/shui1iao/Kat/internal/ss"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func idle17AEAD(t *testing.T, salt []byte) cipher.AEAD {
	t.Helper()
	key := md5.Sum([]byte("source-fixture"))
	sub, e := hkdf.Key(sha1.New, key[:], salt, "ss-subkey", 16)
	if e != nil {
		t.Fatal(e)
	}
	b, e := aes.NewCipher(sub)
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func idle17Wire(t *testing.T, target Address) []byte {
	salt := bytes.Repeat([]byte{0x49}, 16)
	a := idle17AEAD(t, salt)
	return append(salt, a.Seal(nil, make([]byte, 12), append(peerAddr(target, false), []byte("request")...), nil)...)
}
func idleCheckResponse(t *testing.T, version22 bool, wire []byte, want string) {
	t.Helper()
	var p []byte
	var e error
	if version22 {
		h := make([]byte, 16)
		b, _ := aes.NewCipher(key2022())
		b.Decrypt(h, wire[:16])
		a := deriveTest(t, key2022(), h[:8])
		p, e = a.Open(nil, h[4:], wire[16:], nil)
		if e == nil {
			p = p[19:]
		}
	} else {
		p, e = idle17AEAD(t, wire[:16]).Open(nil, make([]byte, 12), wire[16:], nil)
	}
	if e != nil {
		t.Fatal("reply authentication", e)
	}
	_, n, e := SS.ParseAddress(p)
	if e != nil || string(p[n:]) != want {
		t.Fatal("reply body", e, string(p))
	}
}
func TestSSUDPConfiguredListenFamily(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:0", "127.0.0.1:0", "[::]:0"} {
		for _, v22 := range []bool{false, true} {
			name := listen + "/SS2017"
			if v22 {
				name = listen + "/SS2022"
			}
			t.Run(name, func(t *testing.T) {
				ipv6 := listen == "[::]:0"
				if ipv6 {
					probe, e := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
					if e != nil {
						t.Skipf("IPv6 unavailable: %v", e)
					}
					probe.Close()
				}
				in := ssIn()
				if !v22 {
					in = Inbound{Protocol: "shadowsocks", SS: &SSOptions{Method: "aes-128-gcm", Password: "source-fixture", Salts2017: 16}}
				}
				in.Listen = listen
				s := startTest(t, in, nil)
				udp := s.ssListeners[0].socket
				bound := udp.LocalAddr().(*net.UDPAddr)
				tcp := s.Addresses()[0].(*net.TCPAddr)
				if tcp.Port == 0 || bound.Port != tcp.Port {
					t.Fatal("TCP-selected ephemeral port not preserved", tcp, bound)
				}
				network, ip := "udp4", net.IPv4(127, 0, 0, 1)
				if ipv6 {
					network, ip = "udp6", net.IPv6loopback
					if bound.IP.To4() != nil {
						t.Fatal("IPv6 became IPv4")
					}
					raw, _ := udp.SyscallConn()
					var only int
					raw.Control(func(fd uintptr) { only, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY) })
					if only != 1 {
						t.Fatal("explicit IPv6 admitted IPv4")
					}
				} else if bound.IP.To4() == nil {
					t.Fatal("configured IPv4 wildcard became IPv6", bound)
				}
				client, e := net.ListenUDP(network, &net.UDPAddr{IP: ip})
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				target := localUDP(t)
				if ipv6 {
					target.Close()
					target, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
					if e != nil {
						t.Fatal(e)
					}
					defer target.Close()
				}
				dst := addrFromNet(target.LocalAddr())
				wire := idle17Wire(t, dst)
				if v22 {
					wire = udp2022(t, dst, 112, 1, []byte("request"))
				}
				endpoint := &net.UDPAddr{IP: ip, Port: bound.Port}
				if _, e = client.WriteToUDP(wire, endpoint); e != nil {
					t.Fatal(e)
				}
				p, out := recvUDP(t, target)
				if string(p) != "request" {
					t.Fatal("payload", string(p))
				}
				target.WriteToUDP([]byte("reply"), out)
				w, from := recvUDP(t, client)
				if from.Port != tcp.Port {
					t.Fatal("reply source port")
				}
				idleCheckResponse(t, v22, w, "reply")
				if ipv6 {
					v4 := localUDP(t)
					before := s.Stats().Dropped
					v4.WriteToUDP(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bound.Port})
					silentUDP(t, target)
					if s.Stats().Dropped != before {
						t.Fatal("IPv4 reached explicit IPv6 UDP socket")
					}
				}
			})
		}
	}
}

func TestSSUDPIdleTargetAuthorizationAndClock(t *testing.T) {
	s := &Server{}
	s.cfg.Limits.UDPIdle = Duration(5 * time.Minute)
	base := time.Unix(1700000000, 0)
	dst := netip.MustParseAddrPort("127.0.0.1:4567")
	evil := netip.MustParseAddrPort("127.0.0.2:4567")
	a := &udpAssociation{server: s, ssNative: true, allowed: map[netip.AddrPort]time.Time{dst: base}}
	a.activity.Store(base.UnixNano())
	if a.ssIdleExpired(base.Add(70 * time.Second)) {
		t.Fatal("hard60 still active")
	}
	before := a.activity.Load()
	if a.acceptReturn(evil, 1, base.Add(70*time.Second), 5*time.Minute) || a.activity.Load() != before {
		t.Fatal("unknown target renewed")
	}
	if a.acceptReturn(dst, maxDatagram+1, base.Add(70*time.Second), 5*time.Minute) || a.activity.Load() != before {
		t.Fatal("oversize renewed")
	}
	if !a.acceptReturn(dst, 1, base.Add(70*time.Second), 5*time.Minute) {
		t.Fatal("valid >61s target response rejected")
	}
	if a.ssIdleExpired(base.Add(301 * time.Second)) {
		t.Fatal("valid return did not renew")
	}
	if !a.acceptReturn(dst, 1, base.Add(350*time.Second), 5*time.Minute) {
		t.Fatal("exact target was not renewed by valid return")
	}
	before = a.activity.Load()
	if a.acceptReturn(dst, 1, base.Add(650*time.Second), 5*time.Minute) || a.activity.Load() != before || !a.ssIdleExpired(base.Add(650*time.Second)) {
		t.Fatal("expired target revived")
	}
	// Authentic incoming activity may extend the association, never a target that it did not request.
	a.touchSSActivity(base.Add(700 * time.Second))
	if a.acceptReturn(dst, 1, base.Add(701*time.Second), 5*time.Minute) {
		t.Fatal("other activity revived expired target")
	}
	// Monotonic max under racing receive/return activity (race detector).
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); a.touchSSActivity(base.Add(time.Duration(i) * time.Second)) }(i)
	}
	wg.Wait()
	if a.activity.Load() != base.Add(700*time.Second).UnixNano() {
		t.Fatal("older reader moved activity backwards")
	}
	// No behavior expansion for SOCKS/Trojan/AnyTLS target authorization.
	other := &udpAssociation{server: s, allowed: map[netip.AddrPort]time.Time{dst: base}}
	if !other.acceptReturn(dst, 1, base.Add(time.Second), 5*time.Minute) || other.allowed[dst] != base {
		t.Fatal("unrelated protocol target expiry changed")
	}
}

func TestSSUDPConfiguredIdleLifecycle(t *testing.T) {
	baseline, _ := os.ReadDir("/proc/self/fd")
	s := startTest(t, ssIn(), func(c *Config) { c.Limits.UDPIdle = Duration(5 * time.Minute) })
	target, client, mover, evil := localUDP(t), localUDP(t), localUDP(t), localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	rt := s.ssListeners[0].bind.Load().runtime
	first := udp2022(t, dst, 91, 1, []byte("initial"))
	client.WriteToUDP(first, endpoint)
	p, out := recvUDP(t, target)
	if string(p) != "initial" {
		t.Fatal("initial")
	}
	rt.mu.Lock()
	n := rt.associations[ssAssociationID{session: 91}]
	rt.mu.Unlock()
	if n == nil {
		t.Fatal("missing association")
	}
	// Move only last activity/target age, no real 70-second wait; codec fake-clock
	// test independently proves its >61s retained capability and timestamps.
	old := time.Now().Add(-70 * time.Second)
	n.a.activity.Store(old.UnixNano())
	n.a.mu.Lock()
	n.a.allowed[target.LocalAddr().(*net.UDPAddr).AddrPort()] = old
	n.a.mu.Unlock()
	time.Sleep(1100 * time.Millisecond) // existing 1-second lifecycle ticker must not cancel at 60s.
	if n.a.ctx.Err() != nil || s.Stats().UDP != 1 {
		t.Fatal("hard60 association cancellation remains")
	}
	target.WriteToUDP([]byte("after70"), out)
	w, _ := recvUDP(t, client)
	idleCheckResponse(t, true, w, "after70")
	n.a.mu.Lock()
	last := n.a.allowed[target.LocalAddr().(*net.UDPAddr).AddrPort()]
	n.a.mu.Unlock()
	if time.Since(last) > time.Second || time.Since(time.Unix(0, n.a.activity.Load())) > time.Second {
		t.Fatal("legal target reply did not renew idle")
	}
	// Unknown source must not refresh either activity or target permission.
	before := n.a.activity.Load()
	evil.WriteToUDP([]byte("unsolicited"), out)
	silentUDP(t, client)
	if n.a.activity.Load() != before {
		t.Fatal("unknown source kept association alive")
	}
	mover.WriteToUDP(udp2022(t, dst, 91, 2, []byte("migrate")), endpoint)
	_, out2 := recvUDP(t, target)
	if out2.String() != out.String() {
		t.Fatal("valid activity recreated mapping")
	}
	target.WriteToUDP([]byte("moved"), out)
	w, _ = recvUDP(t, mover)
	idleCheckResponse(t, true, w, "moved")
	silentUDP(t, client)
	// Force the existing real reader deadline path to observe an idle-expired timestamp.
	n.a.activity.Store(time.Now().Add(-5*time.Minute - time.Second).UnixNano())
	n.a.outbound4.SetReadDeadline(time.Now())
	if n.a.outbound6 != nil {
		n.a.outbound6.SetReadDeadline(time.Now())
	}
	waitFor(t, func() bool { return s.Stats().UDP == 0 })
	rt.mu.Lock()
	left := len(rt.associations)
	rt.mu.Unlock()
	if left != 0 || s.udpSlots.inUse() != 0 || n.a.queuedBytes.Load() != 0 {
		t.Fatal("idle mapping/slots/queue leaked")
	}
	if _, e := n.a.outbound4.WriteToUDPAddrPort(nil, target.LocalAddr().(*net.UDPAddr).AddrPort()); e == nil {
		t.Fatal("idle socket remained open")
	}
	// A replay/forgery cannot rebuild the released association; fresh auth can.
	mover.WriteToUDP(first, endpoint)
	bad := udp2022(t, dst, 91, 3, []byte("bad"))
	bad[len(bad)-1] ^= 1
	evil.WriteToUDP(bad, endpoint)
	silentUDP(t, target)
	if s.Stats().UDP != 0 {
		t.Fatal("replay/bad tag rebuilt association")
	}
	mover.WriteToUDP(udp2022(t, dst, 91, 3, []byte("fresh")), endpoint)
	p, newout := recvUDP(t, target)
	if string(p) != "fresh" {
		t.Fatal("new authenticated request after idle failed")
	}
	target.WriteToUDP([]byte("new mapping"), newout)
	w, _ = recvUDP(t, mover)
	idleCheckResponse(t, true, w, "new mapping")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := s.Close(ctx); e != nil {
		t.Fatal(e)
	}
	target.Close()
	client.Close()
	mover.Close()
	evil.Close()
	waitFor(t, func() bool { f, _ := os.ReadDir("/proc/self/fd"); return len(f) <= len(baseline)+1 })
}
