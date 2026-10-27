package kernel

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
)

func atAuthenticate(t *testing.T, c net.Conn, password string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	sum := sha256.Sum256([]byte(password))
	md := md5.Sum([]byte(A.DefaultPaddingScheme))
	p := append(sum[:], 0, 0)
	p = append(p, atFrame(4, 0, []byte("v=2\nclient=kat-revocation-test\npadding-md5="+hex.EncodeToString(md[:])))...)
	if e := writeAll(c, p); e != nil {
		t.Fatal(e)
	}
	cmd, _, b := atRead(t, c)
	if cmd != 10 || string(b) != "v=2" {
		t.Fatalf("settings: %d %q", cmd, b)
	}
}

func atTLS(t *testing.T, address string, roots *x509.CertPool) net.Conn {
	t.Helper()
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A FIN for this ID, not EOF/ALERT/session teardown, is the rejection proof.
func atRefused(t *testing.T, c net.Conn, id uint32) {
	t.Helper()
	for {
		cmd, sid, p := atRead(t, c)
		if cmd == 5 {
			t.Fatalf("carrier closed with alert: %q", p)
		}
		if sid != id {
			t.Fatalf("unexpected stream %d (wanted %d)", sid, id)
		}
		if cmd == 2 {
			t.Fatalf("revoked carrier admitted new stream %d: %q", id, p)
		}
		if cmd == 3 {
			return
		}
		if cmd != 7 || len(p) != 0 {
			t.Fatalf("unexpected frame %d %q", cmd, p)
		}
	}
}

func atTCPEcho(t *testing.T, c net.Conn, id uint32, p string) {
	t.Helper()
	if e := writeAll(c, atFrame(2, id, []byte(p))); e != nil {
		t.Fatal(e)
	}
	if got := atPayload(t, c, id, len(p)); string(got) != p {
		t.Fatalf("TCP %d: %q", id, got)
	}
}

func atUDPHeader(a Address, connected bool) []byte {
	p := peerAddr(Address{A.MagicUDPHost, 0}, false)
	mode := byte(0)
	if connected {
		mode = 1
	}
	return append(append(p, mode), peerAddr(a, false)...)
}

func atUDPPacket(a Address, connected bool, p []byte) []byte {
	var b []byte
	if !connected {
		b = append([]byte{0}, net.ParseIP(a.Host).To4()...)
		b = binary.BigEndian.AppendUint16(b, a.Port)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}

func atUDPEcho(t *testing.T, c net.Conn, id uint32, target *net.UDPConn, connected bool, p string) {
	t.Helper()
	a := addrFromNet(target.LocalAddr())
	if e := writeAll(c, atFrame(2, id, atUDPPacket(a, connected, []byte(p)))); e != nil {
		t.Fatal(e)
	}
	got, from := recvUDP(t, target)
	if string(got) != p {
		t.Fatalf("UDP target: %q", got)
	}
	if _, e := target.WriteToUDP(got, from); e != nil {
		t.Fatal(e)
	}
	n := 2 + len(p)
	if !connected {
		n += 7
	}
	if got := atPayload(t, c, id, n); !bytes.Equal(got, atUDPPacket(a, connected, []byte(p))) {
		t.Fatalf("UDP reply: %x", got)
	}
}

func TestAnyTLSCarrierRevocation(t *testing.T) {
	cert, pool := testCert(t)
	for n, change := range []string{"password", "delete", "listen", "protocol"} {
		t.Run(change, func(t *testing.T) {
			in := anyIn(cert)
			in.Listen = reloadPort(t)
			second := anyIn(cert)
			second.Listen = reloadPort(t)
			c0 := socksCfg()
			c0.Inbounds = []Inbound{in, second} // same password elsewhere cannot authorize this carrier
			next := c0
			s := startReloadable(t, c0, &next)
			carrier := atBegin(t, s, pool, 2, in.Listen)
			carrier.SetDeadline(time.Now().Add(8 * time.Second))
			target := echoTCP(t)
			udp := localUDP(t)
			ua := addrFromNet(udp.LocalAddr())
			connected := n%2 == 0
			atOpen(t, carrier, 1, target, []byte("before"))
			atPayload(t, carrier, 1, 6)
			if e := writeAll(carrier, append(atFrame(1, 2, nil), atFrame(2, 2, atUDPHeader(ua, connected))...)); e != nil {
				t.Fatal(e)
			}
			atUDPEcho(t, carrier, 2, udp, connected, "udp-before")
			next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
			switch change {
			case "password":
				o := *in.AnyTLS
				o.Password = "new-password"
				next.Inbounds[0].AnyTLS = &o
			case "delete":
				next.Inbounds = []Inbound{second}
			case "listen":
				next.Inbounds[0].Listen = reloadPort(t)
			case "protocol":
				next.Inbounds[0] = Inbound{Protocol: "socks5", Listen: in.Listen}
			}
			if _, e := s.Reload("revoke"); e != nil {
				t.Fatal(e)
			}
			atOpen(t, carrier, 3, target, []byte("forbidden"))
			atRefused(t, carrier, 3)
			writeAll(carrier, append(atFrame(1, 4, nil), atFrame(2, 4, append(atUDPHeader(ua, connected), atUDPPacket(ua, connected, []byte("forbidden"))...))...))
			atRefused(t, carrier, 4)
			// Both already-established logical flows continue on generation 1.
			for i := 0; i < 3; i++ {
				atTCPEcho(t, carrier, 1, fmt.Sprintf("tcp-after-%d", i))
				atUDPEcho(t, carrier, 2, udp, connected, fmt.Sprintf("udp-after-%d", i))
			}
			if v := s.StatsView().Reload; v.LiveGenerations != 2 || len(v.Retained) != 1 || v.Retained[0].References != 2 {
				t.Fatalf("established flow references: %+v", v)
			}
			// Another listener still accepting the same password is independent.
			other := atBegin(t, s, pool, 2, second.Listen)
			atOpen(t, other, 1, target, []byte("other"))
			atPayload(t, other, 1, 5)
			other.Close()
			if change == "password" {
				bad := atTLS(t, in.Listen, pool)
				sum := sha256.Sum256([]byte(in.AnyTLS.Password))
				writeAll(bad, append(sum[:], 0, 0))
				bad.SetReadDeadline(time.Now().Add(time.Second))
				if _, e := bad.Read(make([]byte, 1)); e == nil {
					t.Fatal("new carrier accepted old password")
				} else if ne, ok := e.(net.Error); ok && ne.Timeout() {
					t.Fatal("old password not rejected promptly")
				}
				bad.Close()
				good := atTLS(t, in.Listen, pool)
				atAuthenticate(t, good, "new-password")
				atOpen(t, good, 1, target, []byte("new"))
				atPayload(t, good, 1, 3)
				good.Close()
			}
			if change == "listen" {
				good := atBegin(t, s, pool, 2, next.Inbounds[0].Listen)
				atOpen(t, good, 1, target, []byte("moved"))
				atPayload(t, good, 1, 5)
				good.Close()
			}
			// Re-add the exact listener/password (or change the password back). No revival.
			next = c0
			if _, e := s.Reload("restore"); e != nil {
				t.Fatal(e)
			}
			atOpen(t, carrier, 5, target, []byte("still-forbidden"))
			atRefused(t, carrier, 5)
			writeAll(carrier, append(atFrame(1, 6, nil), atFrame(2, 6, append(atUDPHeader(ua, connected), atUDPPacket(ua, connected, []byte("still-forbidden"))...))...))
			atRefused(t, carrier, 6)
			atTCPEcho(t, carrier, 1, "tcp-restored")
			atUDPEcho(t, carrier, 2, udp, connected, "udp-restored")
			fresh := atBegin(t, s, pool, 2, in.Listen)
			atOpen(t, fresh, 1, target, []byte("fresh"))
			atPayload(t, fresh, 1, 5)
			fresh.Close()
			writeAll(carrier, append(atFrame(3, 1, nil), atFrame(3, 2, nil)...))
			waitFor(t, func() bool {
				return s.logical.Load() == 0 && s.Stats().UDP == 0 && s.StatsView().Reload.LiveGenerations == 1 && inCodecStreams(s) == 0
			})
			// Idle revoked carrier still exists but retains no generation.
			atOpen(t, carrier, 7, target, []byte("idle-denied"))
			atRefused(t, carrier, 7)
			carrier.Close()
			waitFor(t, func() bool { return s.Stats().Active == 0 })
		})
	}
}

func inCodecStreams(s *Server) int { return s.cfg.Inbounds[0].anytlsServer.Stats().Streams }

// Slow TLS/authentication/target readers never hold the admission lock, and
// none can resurrect the accepting authorization after change-and-restore.
func TestAnyTLSCarrierPendingAcrossReload(t *testing.T) {
	cert, pool := testCert(t)
	for _, stage := range []string{"tls", "auth", "tcp-target", "udp-target"} {
		t.Run(stage, func(t *testing.T) {
			in := anyIn(cert)
			in.Listen = reloadPort(t)
			c0 := socksCfg()
			c0.Inbounds = []Inbound{in}
			next := c0
			s := startReloadable(t, c0, &next)
			var c net.Conn
			if stage == "tls" {
				raw, e := net.DialTimeout("tcp", in.Listen, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { raw.Close() })
				waitFor(t, func() bool { return s.Stats().Active == 1 })
				c = tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "localhost"})
			} else {
				c = atTLS(t, in.Listen, pool)
			}
			if stage == "tcp-target" || stage == "udp-target" {
				atAuthenticate(t, c, in.AnyTLS.Password)
				writeAll(c, atFrame(1, 1, nil))
				cmd, id, _ := atRead(t, c)
				if cmd != 7 || id != 1 {
					t.Fatal("SYNACK", cmd, id)
				}
				if stage == "udp-target" {
					writeAll(c, atFrame(2, 1, peerAddr(Address{A.MagicUDPHost, 0}, false)))
				}
			}
			next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
			o := *in.AnyTLS
			o.Password = "changed"
			next.Inbounds[0].AnyTLS = &o
			done := make(chan error, 1)
			go func() { _, e := s.Reload("pending"); done <- e }()
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("slow handshake/target blocked reload")
			}
			next = c0
			if _, e := s.Reload("restore"); e != nil {
				t.Fatal(e)
			}
			target := echoTCP(t)
			if stage == "tls" || stage == "auth" {
				atAuthenticate(t, c, in.AnyTLS.Password)
				atOpen(t, c, 1, target, []byte("denied"))
			} else if stage == "tcp-target" {
				writeAll(c, atFrame(2, 1, append(peerAddr(target, false), []byte("denied")...)))
			} else {
				writeAll(c, atFrame(2, 1, append([]byte{1}, peerAddr(target, false)...)))
			}
			atRefused(t, c, 1)
			c.Close()
			waitFor(t, func() bool {
				return s.Stats().Active == 0 && s.logical.Load() == 0 && s.StatsView().Reload.LiveGenerations == 1 && inCodecStreams(s) == 0
			})
		})
	}
}

func TestAnyTLSCarrierUnrelatedReloads(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	in.Name = "before"
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	s.SetConfigLoader(func() (Config, error) {
		b, e := json.Marshal(next)
		if e != nil {
			return Config{}, e
		}
		return decodeConfig(b)
	})
	c := atBegin(t, s, pool, 2, in.Listen)
	target := echoTCP(t)
	authority := s.cfg.Inbounds[0].anytlsAuth
	codec := s.cfg.Inbounds[0].anytlsServer
	// Normal, rename/metadata/rules/log, limits/codec budgets, provider-style raw rebuild.
	extra := Inbound{Protocol: "socks5", Listen: reloadPort(t)}
	for i := 0; i < 4; i++ {
		next = c0
		next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
		if i >= 1 {
			next.Inbounds[0].Name = "after"
			next.Inbounds[0].Sniff = &SniffOptions{Enabled: true, TCPPorts: "none", UDPPorts: "none"}
			next.Log = &LogOptions{Level: "error"}
			next.Routing = &RoutingOptions{Final: "direct"}
		}
		if i >= 2 {
			o := *in.AnyTLS
			o.MaxStreams = 16
			o.MaxSessions = 5
			next.Inbounds[0].AnyTLS = &o
			next.Limits.HandshakeTimeout = Duration(2 * time.Second)
			next.Limits.LogicalStreams = 32
		}
		idx := 0
		if i >= 1 {
			next.Inbounds = append([]Inbound{extra}, next.Inbounds...)
			idx = 1
		}
		var e error
		if i == 3 {
			_, e = s.reload("provider", false)
		} else {
			_, e = s.Reload("unrelated")
		}
		if e != nil {
			t.Fatal(e)
		}
		g := s.current()
		if g.cfg.Inbounds[idx].anytlsAuth != authority {
			t.Fatal("unrelated reload revoked authority")
		}
		if i == 2 && g.cfg.Inbounds[idx].anytlsServer == codec {
			t.Fatal("test did not replace budget-dependent codec")
		}
		id := uint32(i + 1)
		atOpen(t, c, id, target, []byte("same-carrier"))
		atPayload(t, c, id, 12)
		writeAll(c, atFrame(3, id, nil))
		waitFor(t, func() bool { return s.logical.Load() == 0 && s.StatsView().Reload.LiveGenerations == 1 })
	}
	if s.Stats().Accepted != 1 {
		t.Fatal("reconnected instead of reusing carrier")
	}
	// Original inbound counter is kept, not silently lost when the name changes.
	var up, down uint64
	for _, v := range s.StatsView().Cumulative.Inbounds {
		up += v.Up
		down += v.Down
	}
	if up != 48 || down != 48 {
		t.Fatalf("inbound byte accounting: %d/%d", up, down)
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
}

// Exercise the exact admission primitive concurrently with real commits. The
// load/check/ref must be a single read-side critical section, not a gen.Load
// followed by a check against some other generation.
func TestAnyTLSCarrierAdmissionCommitRace(t *testing.T) {
	cert, _ := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	a := s.cfg.Inbounds[0].anytlsAuth
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if g := s.refAnyTLS(a); g != nil {
				g.unref()
			}
		}
	}()
	for i := 0; i < 20; i++ {
		if _, e := s.Reload("race-unchanged"); e != nil {
			t.Fatal(e)
		}
	}
	next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
	o := *in.AnyTLS
	o.Password = "changed"
	next.Inbounds[0].AnyTLS = &o
	if _, e := s.Reload("race-revoke"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 1000; i++ {
		if g := s.refAnyTLS(a); g != nil {
			g.unref()
			t.Fatal("post-commit old admission")
		}
	}
	next = c0
	if _, e := s.Reload("race-restore"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 1000; i++ {
		if g := s.refAnyTLS(a); g != nil {
			g.unref()
			t.Fatal("restored old admission")
		}
	}
	close(stop)
	<-done
	waitFor(t, func() bool { return s.StatsView().Reload.LiveGenerations == 1 })
}

func TestAnyTLSCarrierConcurrentStreamOpenReload(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	c := atBegin(t, s, pool, 2, in.Listen)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	target := echoTCP(t)
	started := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for id := uint32(1); ; id++ {
			atOpen(t, c, id, target, []byte("race"))
			accepted := false
			for {
				cmd, sid, p := atRead(t, c)
				if sid != id {
					t.Errorf("unexpected stream %d", sid)
					return
				}
				if cmd == 7 && len(p) == 0 {
					continue
				}
				if cmd == 2 && string(p) == "race" {
					accepted = true
					writeAll(c, atFrame(3, id, nil))
					break
				}
				if cmd == 3 {
					break
				}
				t.Errorf("unexpected frame %d %q", cmd, p)
				return
			}
			waitFor(t, func() bool { return inCodecStreams(s) == 0 })
			if id == 1 {
				if !accepted {
					t.Error("initial stream refused")
				}
				close(started)
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	<-started
	for i := 0; i < 20; i++ {
		if _, e := s.Reload("stream-race"); e != nil {
			t.Fatal(e)
		}
	}
	next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
	o := *in.AnyTLS
	o.Password = "changed"
	next.Inbounds[0].AnyTLS = &o
	if _, e := s.Reload("stream-revoke"); e != nil {
		t.Fatal(e)
	}
	close(stop)
	<-done
	// No scheduler ambiguity: these stream opens begin strictly after commit.
	for id := uint32(10001); id < 10011; id++ {
		atOpen(t, c, id, target, []byte("post-commit"))
		atRefused(t, c, id)
	}
	c.Close()
	waitFor(t, func() bool {
		return s.logical.Load() == 0 && s.Stats().Active == 0 && s.StatsView().Reload.LiveGenerations == 1
	})
}

func TestAnyTLSCarrierFailedPrepareKeepsAuthorization(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	c := atBegin(t, s, pool, 2, in.Listen)
	target := echoTCP(t)
	busy, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
	o := *in.AnyTLS
	o.Password = "changed"
	next.Inbounds[0].AnyTLS = &o
	next.Inbounds = append(next.Inbounds, Inbound{Protocol: "socks5", Listen: busy.Addr().String()})
	if _, e := s.Reload("failed-prepare"); e == nil {
		t.Fatal("expected bind failure")
	}
	atOpen(t, c, 1, target, []byte("not-revoked"))
	atPayload(t, c, 1, 11)
	if s.current().id != 1 {
		t.Fatal("failed reload installed generation")
	}
	c.Close()
	waitFor(t, func() bool { return s.logical.Load() == 0 && s.Stats().Active == 0 })
}

func TestAnyTLSCarrierRevokedStopReleases(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.Listen = reloadPort(t)
	c0 := socksCfg()
	c0.Inbounds = []Inbound{in}
	next := c0
	s := startReloadable(t, c0, &next)
	c := atBegin(t, s, pool, 2, in.Listen)
	target := echoTCP(t)
	udp := localUDP(t)
	ua := addrFromNet(udp.LocalAddr())
	atOpen(t, c, 1, target, []byte("before"))
	atPayload(t, c, 1, 6)
	writeAll(c, append(atFrame(1, 2, nil), atFrame(2, 2, atUDPHeader(ua, true))...))
	atUDPEcho(t, c, 2, udp, true, "before")
	next.Inbounds = append([]Inbound(nil), c0.Inbounds...)
	o := *in.AnyTLS
	o.Password = "changed"
	next.Inbounds[0].AnyTLS = &o
	if _, e := s.Reload("revoke-before-stop"); e != nil {
		t.Fatal(e)
	}
	atOpen(t, c, 3, target, []byte("denied"))
	atRefused(t, c, 3)
	oldCodec := s.cfg.Inbounds[0].anytlsServer
	newCodec := s.current().cfg.Inbounds[0].anytlsServer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	if s.logical.Load() != 0 || s.Stats().Active != 0 || s.Stats().UDP != 0 || s.liveGens.Load() != 0 || oldCodec.Stats().Streams != 0 || oldCodec.Stats().Sessions != 0 || newCodec.Stats().Sessions != 0 {
		t.Fatal("revoked stop leaked stream/session/generation/budget")
	}
}
