package kernel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	VX "github.com/shui1iao/Kat/internal/vlessx"
	"io"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func flowHeader(cmd byte, target Address, flow string) []byte {
	base := peerHeader("vless", cmd, target)
	if flow == "" {
		return base
	}
	b := append([]byte(nil), base[:17]...)
	addon := append([]byte{10, byte(len(flow))}, flow...)
	b = append(b, byte(len(addon)))
	b = append(b, addon...)
	return append(b, base[18:]...)
}
func TestVLESSVisionAuthorizationBeforeDial(t *testing.T) {
	cert, pool := testCert(t)
	var count atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { count.Add(1) })
	in := inFor("vless", cert)
	in.Users[0].Flow = VX.VisionFlow
	s := startTest(t, in, nil)
	for _, raw := range [][]byte{flowHeader(1, target, ""), flowHeader(2, target, VX.VisionFlow), func() []byte { b := flowHeader(1, target, VX.VisionFlow); b[1] ^= 1; return b }(), flowHeader(1, target, "unsupported-flow")} {
		c := dialPeer(t, s, pool)
		writeAll(c, raw)
		c.(interface{ CloseWrite() error }).CloseWrite()
		out, _ := io.ReadAll(c)
		c.Close()
		if len(out) > 0 {
			t.Fatal("unauthorized response")
		}
	}
	if count.Load() != 0 {
		t.Fatal("bad UUID/flow dialed")
	}
	plain := startTest(t, inFor("vless", cert), nil)
	c := dialPeer(t, plain, pool)
	writeAll(c, flowHeader(1, target, VX.VisionFlow))
	c.(interface{ CloseWrite() error }).CloseWrite()
	io.ReadAll(c)
	c.Close()
	if count.Load() != 0 {
		t.Fatal("Vision accepted for empty-flow user")
	}
}
func muxWire(id uint16, status byte, target Address, p []byte) []byte {
	h := []byte{byte(id >> 8), byte(id), status, 1}
	if status == 1 || status == 2 && target.Port != 0 {
		h = append(h, 2)
		h = binary.BigEndian.AppendUint16(h, target.Port)
		h = append(h, peerAddr(target, true)...)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(h)))
	out = append(out, h...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
	return append(out, p...)
}
func readMuxReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	h, e := readN(c, 2)
	if e != nil {
		t.Fatal(e)
	}
	meta, e := readN(c, int(binary.BigEndian.Uint16(h)))
	if e != nil {
		t.Fatal(e)
	}
	if len(meta) < 5 || meta[2] != 2 || meta[4] != 2 {
		t.Fatal("bad reply metadata")
	}
	h, e = readN(c, 2)
	if e != nil {
		t.Fatal(e)
	}
	p, e := readN(c, int(binary.BigEndian.Uint16(h)))
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestVLESSMuxGenerationIsolationAndCancel(t *testing.T) {
	s := startTest(t, inFor("vless", nil), nil)
	target := localUDP(t)
	a := addrFromNet(target.LocalAddr())
	c := dialPeer(t, s, nil)
	header := append([]byte(nil), peerHeader("vless", 3, a)[:19]...)
	writeAll(c, header)
	peerResponse(t, c, "vless")
	writeAll(c, muxWire(1, 1, a, []byte("old")))
	p, oldSocket := recvUDP(t, target)
	if string(p) != "old" {
		t.Fatal("old")
	}
	// End is consumed by library, New reuses ID with a fresh Generation. The old
	// response must not be encoded under the new stream's authority.
	end := []byte{0, 4, 0, 1, 3, 0}
	writeAll(c, append(end, muxWire(1, 1, a, []byte("new"))...))
	p, newSocket := recvUDP(t, target)
	if string(p) != "new" || oldSocket.String() == newSocket.String() {
		t.Fatal("generation failed to change socket")
	}
	target.WriteToUDP([]byte("stale"), oldSocket)
	target.WriteToUDP([]byte("current"), newSocket)
	if string(readMuxReply(t, c)) != "current" {
		t.Fatal("old generation polluted new association")
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().UDP == 0 && s.Stats().Active == 0 })
}
func TestVLESSMuxBadTCPAndOversizeNoTarget(t *testing.T) {
	s := startTest(t, inFor("vless", nil), nil)
	target := localUDP(t)
	a := addrFromNet(target.LocalAddr())
	for _, bad := range [][]byte{func() []byte { b := muxWire(2, 1, a, []byte("x")); b[6] = 1; return b }(), muxWire(2, 1, a, make([]byte, 8193))} {
		c := dialPeer(t, s, nil)
		writeAll(c, peerHeader("vless", 3, a)[:19])
		peerResponse(t, c, "vless")
		writeAll(c, bad)
		c.(interface{ CloseWrite() error }).CloseWrite()
		io.ReadAll(c)
		c.Close()
		silentUDP(t, target)
	}
	waitFor(t, func() bool { return s.Stats().UDP == 0 })
}
func TestVLESSComboValidation(t *testing.T) {
	cert, _ := testCert(t)
	for _, in := range []Inbound{
		{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: testUUID, Flow: VX.VisionFlow}}},
		{Protocol: "vless", Listen: "127.0.0.1:0", TLS: cert, Users: []User{{UUID: testUUID, Flow: VX.VisionFlow}}, Transport: &VTransportOptions{Type: "ws", Path: "/"}},
		{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: testUUID}}, Transport: &VTransportOptions{Type: "grpc", ServiceName: "bad/path"}},
		{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: testUUID}}, Transport: &VTransportOptions{Type: "ws", Path: "/x?ed=1"}},
	} {
		c := Config{Inbounds: []Inbound{in}}
		if c.Validate() == nil {
			t.Fatal("invalid VLESS combo accepted")
		}
	}
}
func TestVLESSLocalRealityHalfClosePeer(t *testing.T) {
	peer := os.Getenv("KAT_VLESS_WIRE_PEER")
	if peer == "" {
		t.Skip("set approved independent wire peer")
	}
	cert, _ := testCert(t)
	pair, e := tls.LoadX509KeyPair(cert.Cert, cert.Key)
	if e != nil {
		t.Fatal(e)
	}
	decoy, e := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if e != nil {
		t.Fatal(e)
	}
	defer decoy.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := decoy.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				if c.(*tls.Conn).Handshake() == nil {
					io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	defer func() { decoy.Close(); <-done }()
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ mode, flow string }{{"tls", VX.VisionFlow}, {"reality", ""}, {"reality", VX.VisionFlow}} {
		in := inFor("vless", cert)
		in.Users[0].Flow = tc.flow
		if tc.mode == "reality" {
			in.TLS = nil
			in.Reality = &RealityOptions{PrivateKey: base64.RawURLEncoding.EncodeToString(priv.Bytes()), ShortIDs: []string{"0100000000000000"}, ServerNames: []string{"localhost"}, Decoy: decoy.Addr().String(), DecoyCA: cert.Cert}
		}
		s := startTest(t, in, nil)
		target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
			writeAll(c, []byte("greeting-before-client\n"))
			b, _ := io.ReadAll(c)
			writeAll(c, append([]byte("reply:"), b...))
		})
		pem, _ := os.ReadFile(cert.Cert)
		cfg := map[string]string{"Front": s.Addresses()[0].String(), "Target": target.String(), "Mode": tc.mode, "Flow": tc.flow, "Certificate": string(pem), "PublicKey": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())}
		raw, _ := json.Marshal(cfg)
		cmd := exec.Command(peer, "halfclose")
		cmd.Stdin = bytes.NewReader(raw)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("wire halfclose %s %s %v %s", tc.mode, tc.flow, e, out)
		}
		t.Log(string(out))
	}
}

func TestVLESSMuxLimitsSourceAndIdle(t *testing.T) {
	s := startTest(t, inFor("vless", nil), func(c *Config) {
		c.Limits.UDPAssociations = 1
		c.Limits.UDPTargets = 1
		c.Limits.UDPIdle = Duration(120 * time.Millisecond)
	})
	target := localUDP(t)
	a := addrFromNet(target.LocalAddr())
	c := dialPeer(t, s, nil)
	writeAll(c, peerHeader("vless", 3, a)[:19])
	peerResponse(t, c, "vless")
	writeAll(c, muxWire(1, 1, a, []byte("allowed")))
	_, out := recvUDP(t, target)
	forger := localUDP(t)
	forger.WriteToUDP([]byte("forged"), out)
	waitFor(t, func() bool { return s.Stats().Dropped > 0 })
	target.WriteToUDP([]byte("valid"), out)
	if string(readMuxReply(t, c)) != "valid" {
		t.Fatal("source filter")
	}
	writeAll(c, muxWire(2, 1, a, []byte("over-limit")))
	silentUDP(t, target)
	waitFor(t, func() bool { return s.Stats().UDP == 0 && s.Stats().Active == 0 })
	if s.logical.Load() != 0 {
		t.Fatal("logical leaked")
	}
}
