package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"lukechampine.com/blake3"
)

// udp2022WithKey is udp2022 with an arbitrary PSK (wrong-key forgery fixture).
func udp2022WithKey(t *testing.T, key []byte, target Address, id, packetID uint64, payload []byte) []byte {
	t.Helper()
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], id)
	binary.BigEndian.PutUint64(header[8:], packetID)
	sub := make([]byte, len(key))
	blake3.DeriveKey(sub, "shadowsocks 2022 session subkey", append(append([]byte(nil), key...), header[:8]...))
	block, e := aes.NewCipher(sub)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := cipher.NewGCM(block)
	body := []byte{0}
	body = binary.BigEndian.AppendUint64(body, uint64(time.Now().Unix()))
	body = append(body, 0, 0)
	body = append(body, peerAddr(target, false)...)
	body = append(body, payload...)
	hb, _ := aes.NewCipher(key)
	wire := make([]byte, 16)
	hb.Encrypt(wire, header[:])
	return append(wire, a.Seal(nil, header[4:], body, nil)...)
}

// drainUDP reads until quiet and returns every datagram payload received.
func drainUDP(c *net.UDPConn, quiet time.Duration) []string {
	var out []string
	b := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(quiet))
		n, _, e := c.ReadFromUDP(b)
		if e != nil {
			return out
		}
		out = append(out, string(b[:n]))
	}
}

// 0.5.20: SIP022 UDP decrypts outside the routing lock and gets the same single
// extra fixed reader (shared process pool) as SS2017. Concurrent readers must
// still accept every packet exactly once, reject forged/replayed/wrong-key
// packets without touching session or source, and migrate only on valid packets.
func TestSS2022ParallelReadExactlyOnceRejectAndMigration(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	prior := len(ss2017ReadSlots)
	s := startTest(t, ssIn(), func(c *Config) { c.Limits.UDPQueue = 256; c.Limits.UDPIdle = Duration(20 * time.Second) })
	waitFor(t, func() bool { return len(ss2017ReadSlots) == prior+1 })
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	target := localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	client, evil, mover := localUDP(t), localUDP(t), localUDP(t)
	const id, packets, copies = 21, 96, 4
	wires := make([][]byte, packets)
	for i := range wires {
		wires[i] = udp2022(t, dst, id, uint64(i), []byte(fmt.Sprintf("p%03d", i)))
	}
	// Target echoes concurrently so replies race with both readers (race detector).
	var echoOut *net.UDPAddr
	var mu sync.Mutex
	got := map[string]int{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			target.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, from, e := target.ReadFromUDP(b)
			if e != nil {
				return
			}
			mu.Lock()
			got[string(b[:n])]++
			echoOut = from
			mu.Unlock()
			target.WriteToUDP(b[:n], from)
		}
	}()
	for i := range packets {
		for range copies {
			client.WriteToUDP(wires[i], endpoint)
		}
		if i%8 == 7 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	<-done
	for i := range packets {
		if k := fmt.Sprintf("p%03d", i); got[k] != 1 {
			t.Fatalf("packet %s accepted %d times", k, got[k])
		}
	}
	if len(got) != packets || s.Stats().UDP != 1 {
		t.Fatalf("unexpected payloads %d / associations %d", len(got), s.Stats().UDP)
	}
	replies := drainUDP(client, 200*time.Millisecond)
	if len(replies) != packets {
		t.Fatalf("%d encrypted replies reached authenticated source, want %d", len(replies), packets)
	}
	// Forged (bad tag), replayed, and wrong-key packets from a new source: all
	// rejected, no association, and no migration of the reply destination.
	dropped := s.Stats().Dropped
	forged := udp2022(t, dst, id, packets+5, []byte("forged"))
	forged[len(forged)-1] ^= 1
	wrong := udp2022WithKey(t, bytes.Repeat([]byte{0x42}, 16), dst, id, packets+6, []byte("wrong-key"))
	for _, w := range [][]byte{forged, wires[3], wrong, wires[packets-1]} {
		evil.WriteToUDP(w, endpoint)
	}
	waitFor(t, func() bool { return s.Stats().Dropped >= dropped+4 })
	silentUDP(t, target)
	if s.Stats().UDP != 1 {
		t.Fatal("rejected packet created association")
	}
	mu.Lock()
	out := echoOut
	mu.Unlock()
	target.WriteToUDP([]byte("still-client"), out)
	// Encrypted SIP022 response must reach the original authenticated source.
	if b, from := recvUDP(t, client); len(b) <= len("still-client") || from.Port != endpoint.Port {
		t.Fatal("reply destination changed")
	}
	silentUDP(t, evil)
	// The forged/wrong-key packet IDs were not consumed: legitimate use works and
	// migrates the authenticated peer to the new source.
	mover.WriteToUDP(udp2022(t, dst, id, packets+5, []byte("migrate")), endpoint)
	if b, _ := recvUDP(t, target); string(b) != "migrate" {
		t.Fatal("legitimate packet after forgery rejected")
	}
	target.WriteToUDP([]byte("to-mover"), out)
	if b, from := recvUDP(t, mover); len(b) <= len("to-mover") || from.Port != endpoint.Port {
		t.Fatal("valid packet did not migrate peer")
	}
	silentUDP(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Close(ctx)
	if len(ss2017ReadSlots) != prior || s.Stats().UDP != 0 {
		t.Fatal("extra reader slot or association leaked after Close")
	}
}
