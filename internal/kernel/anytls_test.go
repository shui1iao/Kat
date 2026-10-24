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
	"fmt"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func anyIn(cert *TLSConfig) Inbound {
	return Inbound{Protocol: "anytls", TLS: cert, AnyTLS: &AnyTLSOptions{Password: "fixture-password", MaxSessions: 4, MaxStreams: 8, SessionStreams: 4}}
}
func atFrame(cmd byte, id uint32, p []byte) []byte {
	b := []byte{cmd}
	b = binary.BigEndian.AppendUint32(b, id)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}
func atRead(t *testing.T, c net.Conn) (byte, uint32, []byte) {
	t.Helper()
	h, e := readN(c, 7)
	if e != nil {
		t.Fatal(e)
	}
	b, e := readN(c, int(binary.BigEndian.Uint16(h[5:])))
	if e != nil {
		t.Fatal(e)
	}
	return h[0], binary.BigEndian.Uint32(h[1:5]), b
}
func atBegin(t *testing.T, s *Server, roots *x509.CertPool, version int, addresses ...string) net.Conn {
	t.Helper()
	var c net.Conn
	if len(addresses) == 0 {
		c = dialPeer(t, s, roots)
	} else {
		var e error
		c, e = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addresses[0], &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		t.Cleanup(func() { c.Close() })
	}
	sum := sha256.Sum256([]byte("fixture-password"))
	p := append(sum[:], 0, 0)
	md := md5.Sum([]byte(A.DefaultPaddingScheme))
	settings := []byte(fmt.Sprintf("v=%d\nclient=kat-test/3\npadding-md5=%s", version, hex.EncodeToString(md[:])))
	p = append(p, atFrame(4, 0, settings)...)
	if e := writeAll(c, p); e != nil {
		t.Fatal(e)
	}
	if version == 2 {
		cmd, _, b := atRead(t, c)
		if cmd != 10 || string(b) != "v=2" {
			t.Fatal("server settings", cmd, string(b))
		}
	}
	return c
}
func atOpen(t *testing.T, c net.Conn, id uint32, target Address, payload []byte) {
	t.Helper()
	p := atFrame(1, id, nil)
	p = append(p, atFrame(2, id, append(peerAddr(target, false), payload...))...)
	if e := writeAll(c, p); e != nil {
		t.Fatal(e)
	}
}
func atPayload(t *testing.T, c net.Conn, id uint32, n int) []byte {
	t.Helper()
	var got []byte
	for len(got) < n {
		cmd, sid, b := atRead(t, c)
		if cmd == 2 && sid == id {
			got = append(got, b...)
		} else if cmd == 5 {
			t.Fatal("unexpected alert", string(b))
		}
	}
	return got
}
func TestAnyTLSV1V2ReuseAndConcurrent(t *testing.T) {
	cert, pool := testCert(t)
	for _, v := range []int{1, 2} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			s := startTest(t, anyIn(cert), nil)
			target := echoTCP(t)
			c := atBegin(t, s, pool, v)
			for i := uint32(1); i <= 2; i++ {
				p := bytes.Repeat([]byte{byte(i)}, 8192)
				atOpen(t, c, i, target, p)
				if got := atPayload(t, c, i, len(p)); !bytes.Equal(got, p) {
					t.Fatal("reuse payload")
				}
				writeAll(c, atFrame(3, i, nil))
				waitFor(t, func() bool { return s.logical.Load() == 0 })
			}
			for i := uint32(3); i <= 6; i++ {
				atOpen(t, c, i, target, bytes.Repeat([]byte{byte(i)}, 1024))
			}
			got := map[uint32][]byte{}
			for n := 0; n < 4; {
				cmd, id, p := atRead(t, c)
				if cmd == 2 {
					got[id] = append(got[id], p...)
					if len(got[id]) == 1024 {
						n++
					}
				}
			}
			for i := uint32(3); i <= 6; i++ {
				if !bytes.Equal(got[i], bytes.Repeat([]byte{byte(i)}, 1024)) {
					t.Fatal("concurrent mix")
				}
				writeAll(c, atFrame(3, i, nil))
			}
			if s.Stats().Accepted != 1 {
				t.Fatal("reuse required reconnect")
			}
			c.Close()
			waitFor(t, func() bool {
				return s.logical.Load() == 0 && s.Stats().Active == 0 && s.cfg.Inbounds[0].anytlsServer.Stats().Streams == 0
			})
		})
	}
}
func TestAnyTLSAuthenticationAndBudgets(t *testing.T) {
	cert, pool := testCert(t)
	var accepts atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { accepts.Add(1); io.Copy(c, c) })
	s := startTest(t, anyIn(cert), func(c *Config) {
		c.Limits.LogicalStreams = 8
		second := anyIn(cert)
		second.Listen = "127.0.0.1:0"
		c.Inbounds = append(c.Inbounds, second)
	})
	for range 7 {
		s.logicalSlots <- struct{}{}
	}
	defer func() {
		for range 7 {
			<-s.logicalSlots
		}
	}()
	if s.cfg.Inbounds[0].anytlsServer != s.cfg.Inbounds[1].anytlsServer {
		t.Fatal("AnyTLS identity not shared")
	}
	bad := dialPeer(t, s, pool)
	writeAll(bad, make([]byte, 34))
	bad.Read(make([]byte, 1))
	bad.Close()
	if accepts.Load() != 0 {
		t.Fatal("unauthenticated dial")
	}
	c := atBegin(t, s, pool, 2)
	atOpen(t, c, 1, target, []byte("one"))
	atPayload(t, c, 1, 3)
	atOpen(t, c, 2, target, []byte("blocked"))
	waitFor(t, func() bool { return s.Stats().Rejected > 0 })
	if accepts.Load() != 1 || s.logical.Load() != 1 {
		t.Fatal("logical budget ignored")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	if s.logical.Load() != 0 || s.cfg.Inbounds[0].anytlsServer.Stats().Streams != 0 || s.cfg.Inbounds[0].anytlsServer.Stats().Sessions != 0 {
		t.Fatal("Serve/callback budget leak")
	}
}
func TestAnyTLSUoTBothModesAndControl(t *testing.T) {
	cert, pool := testCert(t)
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprint(connected), func(t *testing.T) {
			s := startTest(t, anyIn(cert), nil)
			target := localUDP(t)
			if connected {
				target.Close()
				var e error
				target, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { target.Close() })
			}
			client := atBegin(t, s, pool, 2)
			addr := addrFromNet(target.LocalAddr())
			initial := addr
			if connected {
				initial.Host = "localhost"
			}
			header := peerAddr(Address{A.MagicUDPHost, 0}, false)
			mode := byte(0)
			if connected {
				mode = 1
			}
			header = append(header, mode)
			header = append(header, peerAddr(initial, false)...)
			p := []byte("uot-real-target")
			frame := []byte{}
			if !connected {
				frame = append([]byte{0}, net.ParseIP(addr.Host).To4()...)
				frame = binary.BigEndian.AppendUint16(frame, addr.Port)
			}
			frame = binary.BigEndian.AppendUint16(frame, uint16(len(p)))
			frame = append(frame, p...)
			header = append(header, frame...)
			writeAll(client, append(atFrame(1, 1, nil), atFrame(2, 1, header)...))
			got, out := recvUDP(t, target)
			if !bytes.Equal(got, p) {
				t.Fatal("UDP target mismatch")
			}
			forger := localUDP(t)
			if connected {
				forger.Close()
				var e error
				forger, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
				if e != nil {
					t.Fatal(e)
				}
				defer forger.Close()
			}
			forger.WriteToUDP([]byte("bad-source"), out)
			waitFor(t, func() bool { return s.Stats().Dropped > 0 })
			target.WriteToUDP(p, out)
			wantLen := len(p) + 2
			if !connected {
				wantLen += 7
			}
			body := atPayload(t, client, 1, wantLen)
			if !bytes.HasSuffix(body, p) {
				t.Fatal("UDP response")
			}
			writeAll(client, atFrame(3, 1, nil))
			waitFor(t, func() bool { return s.Stats().UDP == 0 && s.logical.Load() == 0 })
			target.WriteToUDP([]byte("after-FIN"), out)
			client.Close()
		})
	}
}
func TestAnyTLSServerFirstAndFINBoundary(t *testing.T) {
	cert, pool := testCert(t)
	s := startTest(t, anyIn(cert), nil)
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { writeAll(c, []byte("welcome")); io.Copy(c, c) })
	c := atBegin(t, s, pool, 2)
	atOpen(t, c, 1, target, nil)
	if string(atPayload(t, c, 1, 7)) != "welcome" {
		t.Fatal("server first")
	}
	writeAll(c, atFrame(3, 1, nil))
	waitFor(t, func() bool { return s.logical.Load() == 0 })
	if st := s.cfg.Inbounds[0].anytlsServer.Stats(); st.Sessions != 1 {
		t.Fatal("FIN killed session")
	}
}
func TestAnyTLSConfigNeverPlaintext(t *testing.T) {
	// Without tls AnyTLS still runs over TLS, with an ephemeral certificate.
	c := Config{Inbounds: []Inbound{{Protocol: "anytls", Listen: "127.0.0.1:0", AnyTLS: &AnyTLSOptions{Password: "x"}}}}
	if e := c.Validate(); e != nil || c.Inbounds[0].tlsConfig == nil || !c.Inbounds[0].ephemeralTLS {
		t.Fatalf("AnyTLS without tls: %v", e)
	}
}
func TestAnyTLSIndependentPeerIntegration(t *testing.T) {
	peer := os.Getenv("KAT_ANYTLS_PEER")
	if peer == "" {
		t.Skip("set independent peer path")
	}
	cert, _ := testCert(t)
	s := startTest(t, anyIn(cert), nil)
	target := echoTCP(t)
	for _, mode := range []string{"client-first", "reuse", "concurrent", "trust-rejection"} {
		cmd := exec.Command(peer, "-server", s.Addresses()[0].String(), "-ca", cert.Cert, "-mode", mode, "-target", target.String())
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v %s", mode, e, out)
		}
		t.Log(string(out))
	}
	first := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { writeAll(c, []byte("welcome")); io.Copy(c, c) })
	cmd := exec.Command(peer, "-server", s.Addresses()[0].String(), "-ca", cert.Cert, "-mode", "server-first", "-target", first.String())
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("server first %v %s", e, out)
	}
	udp1, _ := echoUDP(t)
	udp2, _ := echoUDP(t)
	for _, mode := range []string{"udp-connect", "udp-nonconnect"} {
		out, e := exec.Command(peer, "-server", s.Addresses()[0].String(), "-ca", cert.Cert, "-mode", mode, "-target", udp1.String(), "-second-target", udp2.String()).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v %s", mode, e, out)
		}
	}
	waitFor(t, func() bool { return s.logical.Load() == 0 })
}

func TestAnyTLSSlowFlowCancellation(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.AnyTLS.SlowTimeout = Duration(30 * time.Millisecond)
	s := startTest(t, in, func(c *Config) { c.Limits.Dials = 1; c.Limits.DialTimeout = Duration(time.Second) })
	s.dialSlots <- struct{}{}
	defer func() { <-s.dialSlots }()
	c := atBegin(t, s, pool, 2)
	atOpen(t, c, 1, Address{"127.0.0.1", 9}, nil)
	waitFor(t, func() bool { return s.logical.Load() == 1 })
	// Target dial waits for its bounded quota, so no consumer reads this stream.
	// Two max-sized frames exceed the configured 131072B retained input budget.
	for i := 0; i < 3; i++ {
		if e := writeAll(c, atFrame(2, 1, make([]byte, 65535))); e != nil {
			break
		}
	}
	waitFor(t, func() bool {
		return s.logical.Load() == 0 && s.Stats().Active == 0 && s.cfg.Inbounds[0].anytlsServer.Stats().Streams == 0
	})
	if s.Stats().Dials != 0 {
		t.Fatal("canceled callback leaked dial quota")
	}
}
func TestAnyTLSIdentityStreamLimitAcrossEntries(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.AnyTLS.MaxStreams = 1
	in.AnyTLS.SessionStreams = 1
	s := startTest(t, in, func(c *Config) {
		second := anyIn(cert)
		second.AnyTLS.MaxStreams = 1
		second.AnyTLS.SessionStreams = 1
		second.Listen = "127.0.0.1:0"
		c.Inbounds = append(c.Inbounds, second)
	})
	target := echoTCP(t)
	one := atBegin(t, s, pool, 2)
	atOpen(t, one, 1, target, []byte("live"))
	atPayload(t, one, 1, 4)
	// Connect to another physical inbound while retaining the first logical flow.
	two := atBegin(t, s, pool, 2, s.listeners[1].Addr().String())
	writeAll(two, append(atFrame(1, 1, nil), atFrame(2, 1, peerAddr(target, false))...))
	cmd, id, p := atRead(t, two)
	if cmd != 7 || id != 1 || len(p) == 0 {
		t.Fatal("identity-wide worker budget not enforced")
	}
	if s.logical.Load() != 1 {
		t.Fatal("worker limit bypassed by second entry")
	}
	two.Close()
	one.Close()
	waitFor(t, func() bool { return s.logical.Load() == 0 })
}

func TestAnyTLSSharedPhysicalSessionBudget(t *testing.T) {
	cert, pool := testCert(t)
	in := anyIn(cert)
	in.AnyTLS.MaxSessions = 1
	s := startTest(t, in, func(c *Config) {
		second := anyIn(cert)
		second.AnyTLS.MaxSessions = 1
		second.Listen = "127.0.0.1:0"
		c.Inbounds = append(c.Inbounds, second)
	})
	one := atBegin(t, s, pool, 2)
	target := echoTCP(t)
	atOpen(t, one, 1, target, []byte("one"))
	atPayload(t, one, 1, 3)
	two, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.listeners[1].Addr().String(), &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if e != nil {
		t.Fatal(e)
	}
	defer two.Close()
	two.SetDeadline(time.Now().Add(time.Second))
	_, e = two.Read(make([]byte, 1))
	if e == nil {
		t.Fatal("same identity bypassed session quota")
	}
	if st := s.cfg.Inbounds[0].anytlsServer.Stats(); st.Sessions != 1 {
		t.Fatal("shared session quota", st)
	}
	writeAll(one, atFrame(2, 1, []byte("still-live")))
	if string(atPayload(t, one, 1, 10)) != "still-live" {
		t.Fatal("limit harmed existing session")
	}
	one.Close()
	waitFor(t, func() bool { return s.logical.Load() == 0 })
}
