package sniff

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// clientHello returns the TLS records a crypto/tls client sends first.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: sni == ""})
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Handshake()
	}()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if _, st := TLSClientHello(buf); st != NeedMore || err != nil {
			return buf
		}
	}
}

func TestTLSClientHello(t *testing.T) {
	ch := clientHello(t, "www.Example.COM")
	if h, st := TLSClientHello(ch); st != Done || h != "www.example.com" {
		t.Fatal(h, st)
	}
	if p, h, st := Stream(ch); p != ProtoTLS || h != "www.example.com" || st != Done {
		t.Fatal(p, h, st)
	}
	// Every prefix is NeedMore, never a wrong answer.
	for i := 0; i < len(ch); i++ {
		if _, st := TLSClientHello(ch[:i]); st != NeedMore {
			t.Fatalf("prefix %d: %v", i, st)
		}
	}
	// ClientHello split over two handshake records.
	body := ch[5:]
	n := len(body) / 2
	rec := func(p []byte) []byte {
		return append([]byte{0x16, 3, 1, byte(len(p) >> 8), byte(len(p))}, p...)
	}
	split := append(rec(body[:n]), rec(body[n:])...)
	if h, st := TLSClientHello(split); st != Done || h != "www.example.com" {
		t.Fatal("split", h, st)
	}
	// No SNI (IP-literal server name is not sent): Done, empty host.
	if h, st := TLSClientHello(clientHello(t, "")); st != Done || h != "" {
		t.Fatal("no sni", h, st)
	}
	for _, bad := range [][]byte{
		{0x16, 3, 1, 0, 4, 2, 0, 0, 0}, // ServerHello
		{0x17, 3, 3, 0, 1, 0},          // application data
		{0x16, 9, 9, 0, 1, 1},          // version
		{0x16, 3, 1, 0, 0},             // empty record
	} {
		if _, st := TLSClientHello(bad); st != NotMatch {
			t.Fatalf("%x: %v", bad, st)
		}
	}
	// Corruption never panics.
	for i := 5; i < len(ch); i++ {
		c := append([]byte(nil), ch...)
		c[i] ^= 0xff
		TLSClientHello(c)
	}
}

func TestHTTPHost(t *testing.T) {
	for in, want := range map[string]string{
		"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n":                          "example.com",
		"POST /x HTTP/1.0\r\nUser-Agent: a\r\nhost:  a.b.example:8080\r\n\r\n": "a.b.example",
		"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n":                     "",
		"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n":                            "",
		"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n":                                "",
	} {
		h, st := HTTPHost([]byte(in))
		if st != Done || h != want {
			t.Fatalf("%q: %q %v", in, h, st)
		}
		if p, _, _ := Stream([]byte(in)); p != ProtoHTTP {
			t.Fatal(p)
		}
	}
	for _, more := range []string{"G", "GE", "GET", "GET / HTTP/1.1\r\nHo", "GET / HTTP/1.1\r\nAccept: x\r\n"} {
		if _, st := HTTPHost([]byte(more)); st != NeedMore {
			t.Fatalf("%q: %v", more, st)
		}
	}
	for _, bad := range []string{"SSH-2.0-OpenSSH_9.6\r\n", "\x00\x01", "GET / HTTP/2.0\r\nHost: a\r\n\r\n", "HELO x\r\n"} {
		if _, st := HTTPHost([]byte(bad)); st != NotMatch {
			t.Fatalf("%q: %v", bad, st)
		}
	}
}

// ---- QUIC Initial construction (client side of openInitial) ----

func sealInitial(t *testing.T, version uint32, dcid []byte, pn uint32, frames []byte) []byte {
	t.Helper()
	salt, kl, il, hl := saltV1, "quic key", "quic iv", "quic hp"
	typ := byte(0)
	if version == quicV2 {
		salt, kl, il, hl = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
		typ = 1
	}
	if version == quicDraft29 {
		salt = saltDraft29
	}
	initial, _ := hkdf.Extract(sha256.New, dcid, salt)
	client := expandLabel(initial, "client in", 32)
	key, iv, hp := expandLabel(client, kl, 16), expandLabel(client, il, 12), expandLabel(client, hl, 16)
	// Pad the payload so the datagram is >= 1200 bytes.
	for len(frames) < 1150 {
		frames = append(frames, 0)
	}
	hdr := []byte{0xc0 | typ<<4 | 3}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 4, 1, 2, 3, 4) // scid
	hdr = append(hdr, 0)             // token length
	length := 4 + len(frames) + 16
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(uint64(pn) >> (8 * i))
	}
	ct := aead.Seal(nil, nonce, frames, hdr)
	pkt := append(hdr, ct...)
	hb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hb.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func cryptoFrame(off int, data []byte) []byte {
	f := []byte{0x06}
	f = appendVarint(f, uint64(off))
	f = appendVarint(f, uint64(len(data)))
	return append(f, data...)
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return append(b, 0x40|byte(v>>8), byte(v))
	}
	return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// quicClientHello returns a real TLS 1.3 ClientHello from crypto/tls's QUIC
// API; extra bytes of transport parameters make it span several packets.
func quicClientHello(t *testing.T, sni string, extra int) []byte {
	t.Helper()
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	tp := make([]byte, 0, 4+extra)
	tp = appendVarint(tp, 0x3fff) // a reserved-style parameter id
	tp = appendVarint(tp, uint64(extra))
	tp = append(tp, make([]byte, extra)...)
	q.SetTransportParameters(tp)
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for {
		ev := q.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			t.Fatal("no ClientHello")
		case tls.QUICWriteData:
			if ev.Level == tls.QUICEncryptionLevelInitial {
				return append([]byte(nil), ev.Data...)
			}
		}
	}
}

func TestQUICInitial(t *testing.T) {
	dcid := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	for _, v := range []uint32{quicV1, quicV2, quicDraft29} {
		ch := quicClientHello(t, "quic.example", 0)
		pkt := sealInitial(t, v, dcid, 0, cryptoFrame(0, ch))
		if !IsInitial(pkt) {
			t.Fatalf("%x: not initial", v)
		}
		var q QUIC
		if h, st := q.Add(pkt); st != Done || h != "quic.example" {
			t.Fatalf("version %x: %q %v", v, h, st)
		}
	}
	// A ClientHello over two Initial packets, second part first (PING and
	// ACK frames mixed in), coalesced with trailing bytes.
	ch := quicClientHello(t, "big.quic.example", 1500)
	if len(ch) < 1500 {
		t.Fatal(len(ch))
	}
	n := 1000
	p1 := sealInitial(t, quicV1, dcid, 0, append([]byte{0x01}, cryptoFrame(0, ch[:n])...))
	p2 := sealInitial(t, quicV1, dcid, 1, append([]byte{0x02, 0, 0, 0, 0}, cryptoFrame(n, ch[n:])...))
	var q QUIC
	if _, st := q.Add(append(p2, 0, 0, 0)); st != NeedMore {
		t.Fatal("first part", st)
	}
	if h, st := q.Add(p1); st != Done || h != "big.quic.example" {
		t.Fatal("reassembled", h, st)
	}
	// Not Initial / not QUIC / wrong keys.
	short := append([]byte{0x40}, make([]byte, 40)...)
	if IsInitial(short) || IsInitial([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("IsInitial")
	}
	bad := bytes.Clone(sealInitial(t, quicV1, dcid, 0, cryptoFrame(0, ch[:100])))
	bad[len(bad)-1] ^= 1
	var q2 QUIC
	if _, st := q2.Add(bad); st != NotMatch {
		t.Fatal("tampered", st)
	}
	// DNS on 443/udp and random bytes: NotMatch, no panic.
	var q3 QUIC
	for i := 0; i < 2000; i++ {
		b := make([]byte, 1200)
		for j := range b {
			b[j] = byte(i*31 + j*7)
		}
		b[0] = 0xc0
		binary.BigEndian.PutUint32(b[1:], quicV1)
		q3.Add(b)
	}
	// Truncations of a valid packet never panic.
	full := sealInitial(t, quicV1, dcid, 0, cryptoFrame(0, ch[:200]))
	for i := 0; i < len(full); i++ {
		var q4 QUIC
		q4.Add(full[:i])
	}
}
