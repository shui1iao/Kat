//go:build linux

package kernel

import (
	"bytes"
	"encoding/binary"
	SS "github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSS2022BatchLeaseFallbackAndClear(t *testing.T) {
	if ss2022DownLeases*ss2022DownLeaseBytes > 16*65535 {
		t.Fatal("original total budget exceeded")
	}
	wire, key, _ := ss2022LifecycleWire(t, SS.AES128GCM2022, Address{"127.0.0.1", 80}, 0)
	srv, e := SS.NewServer(SS.Config{Method: SS.AES128GCM2022, Key: key})
	if e != nil {
		t.Fatal(e)
	}
	raw := &ss2022LifecycleClient{input: bytes.NewReader(wire), closed: make(chan struct{})}
	codec, e := srv.Accept(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer codec.Close()
	reader, writer := ss2017TCPPair(t)
	reader.SetDeadline(time.Now().Add(time.Second))
	writer.SetDeadline(time.Now().Add(time.Second))
	data := bytes.Repeat([]byte{0x63}, 65535)
	sent := make(chan error, 1)
	go func() { _, e := writer.Write(data); sent <- e }()
	end := time.Now().Add(time.Second)
	for ss2022Ready(reader) < len(data) && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	var held [][]byte
	for i := 0; i < ss2022DownLeases; i++ {
		held = append(held, leaseSS2022Down())
	}
	dst := &encryptedStream{raw, codec}
	if used, e := trySS2022DownBatch(dst, reader, &ss2022DownConn{reader}, 16384); used || e != nil {
		t.Fatal("exhaustion did not fall back", used, e)
	}
	for _, b := range held {
		releaseSS2022Down(b)
	}
	var last atomic.Int64
	if used, e := trySS2022DownBatch(&activityStream{dst, &last}, &activityStream{reader, &last}, &ss2022DownConn{reader}, 16384); !used || e != nil {
		t.Fatal(used, e)
	}
	if e := <-sent; e != nil {
		t.Fatal(e)
	}
	if last.Load() == 0 || len(ss2022DownSlots) != 0 {
		t.Fatal("activity or lease leak")
	}
	for i := 0; i < ss2022DownLeases; i++ {
		b := leaseSS2022Down()
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("not cleared")
		}
		held[i] = b
	}
	for _, b := range held {
		releaseSS2022Down(b)
	}
}

func TestSS2022BatchRealTargetWire(t *testing.T) {
	payload := make([]byte, 512*1024)
	for i := range payload {
		payload[i] = byte(i*19 + 7)
	}
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { c.Write(payload); c.(*net.TCPConn).CloseWrite(); io.Copy(io.Discard, c) })
	s := startTest(t, ssIn(), nil)
	wire, _, _ := ss2022LifecycleWire(t, SS.AES128GCM2022, target, 0)
	peer := dialPeer(t, s, nil)
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	writeAll(peer, wire)
	salt := make([]byte, 16)
	if _, e := io.ReadFull(peer, salt); e != nil {
		t.Fatal(e)
	}
	a := deriveTest(t, key2022(), salt)
	nonce := make([]byte, 12)
	open := func(b []byte) []byte {
		p, e := a.Open(nil, nonce, b, nil)
		if e != nil {
			t.Fatal(e)
		}
		for i := range nonce {
			nonce[i]++
			if nonce[i] != 0 {
				break
			}
		}
		return p
	}
	h := make([]byte, 43)
	if _, e := io.ReadFull(peer, h); e != nil {
		t.Fatal(e)
	}
	p := open(h)
	n := int(binary.BigEndian.Uint16(p[25:]))
	var got []byte
	for len(got) < len(payload) {
		b := make([]byte, n+16)
		if _, e := io.ReadFull(peer, b); e != nil {
			t.Fatal(e)
		}
		got = append(got, open(b)...)
		if len(got) == len(payload) {
			break
		}
		b = make([]byte, 18)
		if _, e := io.ReadFull(peer, b); e != nil {
			t.Fatal(e)
		}
		n = int(binary.BigEndian.Uint16(open(b)))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}
