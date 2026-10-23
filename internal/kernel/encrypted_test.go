package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"lukechampine.com/blake3"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func ssIn() Inbound {
	return Inbound{Protocol: "shadowsocks", SS: &SSOptions{Method: "2022-blake3-aes-128-gcm", Key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 16)), TCPSalts: 16, Salts2017: 16, Sessions: 4}}
}
func key2022() []byte { return bytes.Repeat([]byte{0x41}, 16) }
func deriveTest(t *testing.T, key, salt []byte) cipher.AEAD {
	t.Helper()
	sub := make([]byte, 16)
	blake3.DeriveKey(sub, "shadowsocks 2022 session subkey", append(append([]byte(nil), key...), salt...))
	block, e := aes.NewCipher(sub)
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	return a
}

// Independently assembled wire fixture for integration boundaries. No production
// ss encoder/helper is called; peers validate positive interoperability separately.
func tcp2022(t *testing.T, target Address, saltByte byte) []byte {
	salt := bytes.Repeat([]byte{saltByte}, 16)
	a := deriveTest(t, key2022(), salt)
	variable := append(peerAddr(target, false), 0, 1, 0)
	variable = append(variable, []byte("initial")...)
	fixed := []byte{0}
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))
	wire := append(salt, a.Seal(nil, make([]byte, 12), fixed, nil)...)
	nonce := make([]byte, 12)
	nonce[0] = 1
	return append(wire, a.Seal(nil, nonce, variable, nil)...)
}
func udp2022(t *testing.T, target Address, id, packetID uint64, payload []byte) []byte {
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], id)
	binary.BigEndian.PutUint64(header[8:], packetID)
	a := deriveTest(t, key2022(), header[:8])
	body := []byte{0}
	body = binary.BigEndian.AppendUint64(body, uint64(time.Now().Unix()))
	body = append(body, 0, 0)
	body = append(body, peerAddr(target, false)...)
	body = append(body, payload...)
	block, e := aes.NewCipher(key2022())
	if e != nil {
		t.Fatal(e)
	}
	wire := make([]byte, 16)
	block.Encrypt(wire, header[:])
	return append(wire, a.Seal(nil, header[4:], body, nil)...)
}
func requireRST(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1024]byte
	_, e := c.Read(b[:])
	if !errors.Is(e, syscall.ECONNRESET) {
		t.Fatalf("wanted uniform RST, got %v", e)
	}
}
func TestSS2022SharedTCPReplayAndUniformRST(t *testing.T) {
	var accepts atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { accepts.Add(1); io.Copy(c, c) })
	in := ssIn()
	s := startTest(t, in, func(c *Config) {
		second := ssIn()
		second.Listen = "127.0.0.1:0"
		c.Inbounds = append(c.Inbounds, second)
	})
	if s.cfg.Inbounds[0].ssRuntime != s.cfg.Inbounds[1].ssRuntime {
		t.Fatal("same-key protection not shared")
	}
	wire := tcp2022(t, target, 1)
	c := dialPeer(t, s, nil)
	writeAll(c, wire)
	waitFor(t, func() bool { return accepts.Load() == 1 })
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
	replay, e := net.Dial("tcp", s.Addresses()[1].String())
	if e != nil {
		t.Fatal(e)
	}
	writeAll(replay, wire)
	requireRST(t, replay)
	replay.Close()
	// A short first Read must fail, never ReadFull-reassemble into an accepted request.
	short := dialPeer(t, s, nil)
	writeAll(short, wire[:1])
	requireRST(t, short)
	short.Close()
	bad := dialPeer(t, s, nil)
	corrupt := bytes.Clone(tcp2022(t, target, 2))
	corrupt[20] ^= 1
	writeAll(bad, corrupt)
	requireRST(t, bad)
	bad.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
	if accepts.Load() != 1 {
		t.Fatal("unauthenticated/replayed request dialed")
	}
}
func TestSS2022ProtectionCapacityClosed(t *testing.T) {
	in := ssIn()
	in.SS.TCPSalts = 1
	s := startTest(t, in, nil)
	target := echoTCP(t)
	first := dialPeer(t, s, nil)
	writeAll(first, tcp2022(t, target, 3))
	waitFor(t, func() bool { return s.cfg.Inbounds[0].ssRuntime.codec.Stats().TCPSalts == 1 })
	first.Close()
	second := dialPeer(t, s, nil)
	writeAll(second, tcp2022(t, target, 4))
	requireRST(t, second)
	second.Close()
}
func recvUDP(t *testing.T, c *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 65535)
	n, a, e := c.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	return b[:n], a
}
func silentUDP(t *testing.T, c *net.UDPConn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var b [256]byte
	if _, _, e := c.ReadFromUDP(b[:]); e == nil {
		t.Fatal("unexpected UDP forward/reply")
	}
}
func localUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestSS2022NativeUDPMigrationIsolation(t *testing.T) {
	s := startTest(t, ssIn(), func(c *Config) {
		second := ssIn()
		second.Listen = "127.0.0.1:0"
		c.Inbounds = append(c.Inbounds, second)
	})
	target := localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	client, other := localUDP(t), localUDP(t)
	endpoint := func(i int) *net.UDPAddr {
		a, e := net.ResolveUDPAddr("udp", s.Addresses()[i].String())
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	// Bad tag cannot create any association, destination socket, or advance replay state.
	bad := udp2022(t, dst, 7, 100000, []byte("bad"))
	bad[len(bad)-1] ^= 1
	other.WriteToUDP(bad, endpoint(0))
	silentUDP(t, target)
	if s.Stats().UDP != 0 {
		t.Fatal("unauthenticated association")
	}
	first := udp2022(t, dst, 7, 0, []byte("first"))
	client.WriteToUDP(first, endpoint(0))
	got, out := recvUDP(t, target)
	if string(got) != "first" {
		t.Fatal("first payload")
	}
	other.WriteToUDP(first, endpoint(1))
	waitFor(t, func() bool { return s.Stats().Dropped >= 2 })
	target.WriteToUDP([]byte("reply-original"), out)
	_, from := recvUDP(t, client)
	if from.Port != endpoint(0).Port {
		t.Fatal("original listener changed by replay")
	}
	silentUDP(t, other)
	// Valid new packet authenticates a new source and listener. Same session retains
	// its destination socket, not a source-keyed second association.
	second := udp2022(t, dst, 7, 1, []byte("migrate"))
	other.WriteToUDP(second, endpoint(1))
	got, out2 := recvUDP(t, target)
	if string(got) != "migrate" || out2.String() != out.String() {
		t.Fatal("session incorrectly keyed by source")
	}
	if s.Stats().UDP != 1 {
		t.Fatal("migration allocated second association")
	}
	target.WriteToUDP([]byte("latest-peer"), out)
	_, from = recvUDP(t, other)
	if from.Port != endpoint(1).Port {
		t.Fatal("wrong reply listener")
	}
	silentUDP(t, client)
	// A far-ahead forged tag does not advance the window; legitimate next works.
	other.WriteToUDP(bad, endpoint(1))
	other.WriteToUDP(udp2022(t, dst, 7, 2, []byte("after-bad")), endpoint(1))
	got, _ = recvUDP(t, target)
	if string(got) != "after-bad" {
		t.Fatal("bad tag advanced window")
	}
	other.WriteToUDP(udp2022(t, dst, 7, 2048, []byte("advance")), endpoint(1))
	recvUDP(t, target)
	other.WriteToUDP(udp2022(t, dst, 7, 3, []byte("outside-window")), endpoint(1))
	silentUDP(t, target)
	// Unknown response source must not gain an encode capability.
	forger := localUDP(t)
	forger.WriteToUDP([]byte("injected"), out)
	silentUDP(t, other)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := s.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if s.Stats().UDP != 0 {
		t.Fatal("native associations leaked on stop")
	}
}
func TestSSNativeLimitsIdleAndFD(t *testing.T) {
	baseline, _ := os.ReadDir("/proc/self/fd")
	s := startTest(t, ssIn(), func(c *Config) {
		c.Limits.UDPAssociations = 1
		c.Limits.UDPTargets = 1
		c.Limits.UDPIdle = Duration(100 * time.Millisecond)
	})
	target := localUDP(t)
	client := localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	client.WriteToUDP(udp2022(t, dst, 1, 0, []byte("one")), endpoint)
	recvUDP(t, target)
	client.WriteToUDP(udp2022(t, dst, 2, 0, []byte("excess")), endpoint)
	silentUDP(t, target)
	if s.Stats().UDP > 1 {
		t.Fatal("association bound")
	}
	otherTarget := localUDP(t)
	client.WriteToUDP(udp2022(t, addrFromNet(otherTarget.LocalAddr()), 1, 1, []byte("target-limit")), endpoint)
	silentUDP(t, otherTarget)
	waitFor(t, func() bool { return s.Stats().UDP == 0 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := s.Close(ctx); e != nil {
		t.Fatal(e)
	}
	target.Close()
	client.Close()
	otherTarget.Close()
	waitFor(t, func() bool { f, _ := os.ReadDir("/proc/self/fd"); return len(f) <= len(baseline)+1 })
}
func TestEncryptedConfigAndIdle(t *testing.T) {
	for _, in := range []Inbound{{Protocol: "shadowsocks", SS: &SSOptions{Method: "aes-128-cfb", Password: "x"}}, {Protocol: "shadowsocks", SS: &SSOptions{Method: "2022-blake3-aes-128-gcm", Password: "bad"}}, {Protocol: "snell", Snell: &SnellOptions{Version: 6, PSK: "x"}}, {Protocol: "snell", Snell: &SnellOptions{Version: 4, PSK: "x", Obfs: "tls"}}} {
		in.Listen = "127.0.0.1:0"
		c := Config{Inbounds: []Inbound{in}}
		if c.Validate() == nil {
			t.Fatal("unsupported encrypted config accepted")
		}
	}
	sn := Inbound{Protocol: "snell", Snell: &SnellOptions{Version: 4, PSK: "snell-fixture", Obfs: "none"}}
	s := startTest(t, sn, nil)
	if s.cfg.Inbounds[0].snellServer == nil {
		t.Fatal("missing codec")
	}
	target := echoTCP(t)
	old := startTest(t, inFor("socks5", nil), func(c *Config) { c.Limits.TCPIdle = Duration(40 * time.Millisecond) })
	c := dialPeer(t, old, nil)
	socksGreeting(t, c, false, "")
	writeAll(c, peerHeader("socks5", 1, target))
	peerResponse(t, c, "socks5")
	waitFor(t, func() bool { return old.Stats().Active == 0 })
}

func TestDatagramQueueByteBudget(t *testing.T) {
	s := startTest(t, ssIn(), func(c *Config) { c.Limits.UDPQueueBytes = 4 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &udpAssociation{server: s, ctx: ctx, queue: make(chan packet, 4)}
	a.enqueue(packet{payload: []byte("abc")})
	a.enqueue(packet{payload: []byte("de")})
	if len(a.queue) != 1 || a.queuedBytes.Load() != 3 || s.Stats().Dropped != 1 {
		t.Fatal("UDP byte budget not enforced")
	}
}
func TestSnellSamePSKShared(t *testing.T) {
	in := Inbound{Protocol: "snell", Snell: &SnellOptions{Version: 4, PSK: "shared-psk", Obfs: "none"}}
	s := startTest(t, in, func(c *Config) {
		c.Inbounds = append(c.Inbounds, Inbound{Protocol: "snell", Listen: "127.0.0.1:0", Snell: &SnellOptions{Version: 5, PSK: "shared-psk", Obfs: "none"}})
	})
	if s.cfg.Inbounds[0].snellServer != s.cfg.Inbounds[1].snellServer {
		t.Fatal("same Snell PSK not shared")
	}
}

func TestSnellIntegratedReplayRejectAndStop(t *testing.T) {
	peer := os.Getenv("KAT_SNELL_PEER")
	if peer == "" {
		t.Skip("set KAT_SNELL_PEER to independent fixed client")
	}
	var accepts atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { accepts.Add(1); io.Copy(c, c) })
	in := Inbound{Protocol: "snell", Snell: &SnellOptions{Version: 4, PSK: "snell-core-fixture-psk", Obfs: "none", ReplayCapacity: 2}}
	s := startTest(t, in, func(c *Config) {
		c.Inbounds = append(c.Inbounds, Inbound{Protocol: "snell", Listen: "127.0.0.1:0", Snell: &SnellOptions{Version: 5, PSK: "snell-core-fixture-psk", Obfs: "none", ReplayCapacity: 2}})
	})
	wire := captureSnell(t, peer, target)
	c := dialPeer(t, s, nil)
	writeAll(c, wire)
	waitFor(t, func() bool { return accepts.Load() == 1 })
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
	for _, bad := range [][]byte{wire, func() []byte { b := bytes.Clone(wire); b[20] ^= 1; return b }()} {
		c, e := net.Dial("tcp", s.Addresses()[1].String())
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		writeAll(c, bad)
		var b [256]byte
		if n, e := c.Read(b[:]); e == nil || n > 0 {
			t.Fatal("bad Snell returned data")
		}
		c.Close()
	}
	if accepts.Load() != 1 {
		t.Fatal("Snell unauthenticated/replay target dial")
	}
	// A second valid request retains an unfinished client input. Service stop must
	// cancel and join it, rather than leaving a session/target/socket behind.
	c = dialPeer(t, s, nil)
	wire2 := captureSnell(t, peer, target)
	if len(wire2) < 23 {
		t.Fatal("short capture")
	}
	writeAll(c, wire2[:len(wire2)-23])
	waitFor(t, func() bool { return accepts.Load() == 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	if got := s.Stats(); got.Active != 0 || got.Handshakes != 0 {
		t.Fatal("Snell resources not released", got)
	}
}
func captureSnell(t *testing.T, peer string, target Address) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.bin")
	out, e := exec.Command(peer, "-capture", path, "-target1", target.String()).CombinedOutput()
	if e != nil {
		t.Fatalf("capture %v %s", e, out)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestSSAdmissionRST(t *testing.T) {
	s := startTest(t, ssIn(), func(c *Config) { c.Limits.Handshakes = 1 })
	c := dialPeer(t, s, nil)
	waitFor(t, func() bool { return s.Stats().Handshakes == 1 })
	other := dialPeer(t, s, nil)
	requireRST(t, other)
	other.Close()
	c.Close()
}
func TestSharedIdentityConfigConflicts(t *testing.T) {
	a := ssIn()
	b := ssIn()
	a.Listen = "127.0.0.1:0"
	b.Listen = "127.0.0.1:0"
	b.SS.TCPSalts++
	c := Config{Inbounds: []Inbound{a, b}}
	if c.Validate() == nil {
		t.Fatal("conflicting SS protection config accepted")
	}
	c = Config{Inbounds: []Inbound{{Protocol: "snell", Listen: "127.0.0.1:0", Snell: &SnellOptions{Version: 4, PSK: "same", Obfs: "none"}}, {Protocol: "snell", Listen: "127.0.0.1:0", Snell: &SnellOptions{Version: 5, PSK: "same", Obfs: "http"}}}}
	if c.Validate() == nil {
		t.Fatal("conflicting Snell identity obfs accepted without shared protection")
	}
}

func TestSS2017NativeSourceIdentity(t *testing.T) {
	in := Inbound{Protocol: "shadowsocks", SS: &SSOptions{Method: "aes-128-gcm", Password: "source-fixture", Salts2017: 16}}
	s := startTest(t, in, nil)
	target := localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	one, two := localUDP(t), localUDP(t)
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	// EVP_BytesToKey 16-byte key, then specified HKDF-SHA1 per-datagram salt.
	key := md5.Sum([]byte("source-fixture"))
	encode := func(saltByte byte, payload string) []byte {
		salt := bytes.Repeat([]byte{saltByte}, 16)
		sub := make([]byte, 16)
		if _, e := io.ReadFull(hkdf.New(sha1.New, key[:], salt, []byte("ss-subkey")), sub); e != nil {
			t.Fatal(e)
		}
		block, _ := aes.NewCipher(sub)
		a, _ := cipher.NewGCM(block)
		body := append(peerAddr(dst, false), []byte(payload)...)
		return append(salt, a.Seal(nil, make([]byte, 12), body, nil)...)
	}
	first := encode(10, "one")
	one.WriteToUDP(first, endpoint)
	b, out1 := recvUDP(t, target)
	if string(b) != "one" {
		t.Fatal("first payload")
	}
	two.WriteToUDP(encode(11, "two"), endpoint)
	b, out2 := recvUDP(t, target)
	if string(b) != "two" || out1.String() == out2.String() || s.Stats().UDP != 2 {
		t.Fatal("2017 incorrectly merged source identities")
	}
	target.WriteToUDP([]byte("reply1"), out1)
	recvUDP(t, one)
	silentUDP(t, two)
	target.WriteToUDP([]byte("reply2"), out2)
	recvUDP(t, two)
	silentUDP(t, one)
	two.WriteToUDP(first, endpoint)
	silentUDP(t, target)
	bad := encode(12, "bad")
	bad[len(bad)-1] ^= 1
	one.WriteToUDP(bad, endpoint)
	silentUDP(t, target)
	if s.Stats().UDP != 2 {
		t.Fatal("bad tag changed association state")
	}
}

func TestSSShutdownHandshakeRST(t *testing.T) {
	s := startTest(t, ssIn(), nil)
	c := dialPeer(t, s, nil)
	waitFor(t, func() bool { return s.Stats().Handshakes == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	requireRST(t, c)
	c.Close()
}
