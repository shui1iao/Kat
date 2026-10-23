package vlessx

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func udp443Probe(t *testing.T, p *peerProc, allow bool) {
	t.Helper()
	control, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), time.Second)
	must(t, e)
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	must(t, writeFull(control, []byte{5, 1, 0}))
	var hello [2]byte
	_, e = io.ReadFull(control, hello[:])
	must(t, e)
	must(t, writeFull(control, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}))
	var reply [10]byte
	_, e = io.ReadFull(control, reply[:])
	must(t, e)
	udp, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, e)
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(750 * time.Millisecond))
	relay := &net.UDPAddr{IP: net.IPv4(reply[4], reply[5], reply[6], reply[7]), Port: int(reply[8])<<8 | int(reply[9])}
	pdu := []byte{0, 0, 0, 1, 127, 0, 0, 1, 1, 187, 0x42, 0x43}
	_, e = udp.WriteToUDP(pdu, relay)
	must(t, e)
	var b [128]byte
	n, _, e := udp.ReadFromUDP(b[:])
	if allow {
		must(t, e)
		if n != len(pdu) || !bytes.Equal(b[:n], pdu) {
			t.Fatal(b[:n])
		}
	} else if e == nil {
		t.Fatal("default Vision UDP443 unexpectedly forwarded")
	}
}
func TestXrayUDP443ClientPolicy(t *testing.T) {
	if os.Getenv("KAT_VLESSX_PEER") == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	cert := certFor(t, "front.test")
	for _, allow := range []bool{false, true} {
		name := "default-denied"
		flow := VisionFlow
		if allow {
			name = "explicit-udp443"
			flow += "-udp443"
		}
		t.Run(name, func(t *testing.T) {
			front := startFront(t, "tls", VisionFlow, cert, nil, func(d Datagram) (Address, []byte, error) {
				if d.Target != (Address{"127.0.0.1", 443}) {
					return Address{}, nil, ErrWire
				}
				return d.Target, d.Payload, nil
			})
			p := startPeer(t, front.ln.Addr().String(), "tls", flow, cert, nil, nil)
			udp443Probe(t, p, allow)
			expected := int32(0)
			if allow {
				expected = 1
			}
			if front.udp.Load() != expected {
				t.Fatal(front.udp.Load())
			}
			t.Log("No listener or dial on port443; callback-only policy test")
		})
	}
}
func TestRealityClientVersionPolicy(t *testing.T) {
	if os.Getenv("KAT_VLESSX_PEER") == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	cert := certFor(t, "front.test")
	decoy := startDecoy(t, cert)
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, e)
	rs, e := NewRealityServer(context.Background(), RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: certRoots(t, cert), MinClientVersion: []byte{27, 0, 0}})
	must(t, e)
	front := startFront(t, "reality", VisionFlow, cert, rs)
	p := startPeer(t, front.ln.Addr().String(), "reality", VisionFlow, cert, priv.PublicKey().Bytes(), nil)
	c := socksConnect(t, p, Address{"127.0.0.1", 1})
	defer c.Close()
	c.SetDeadline(time.Now().Add(750 * time.Millisecond))
	c.Write([]byte("version-rejected"))
	var b [1]byte
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("version accepted")
	}
	if front.requests.Load() != 0 {
		t.Fatal("request exposed")
	}
}
