package kernel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// Independently assembled SS2022 upload: request header (tcp2022 layout) followed
// by large tail records, so the kernel relay's 16384B caller reads records larger
// than its buffer through the SS2022 resident receive buffer.
func TestSS2022ResidentKernelRelayUpload(t *testing.T) {
	sizes := []int{32734, 32734, 65535, 16385, 32734}
	var plain []byte
	for i, n := range sizes {
		for j := 0; j < n; j++ {
			plain = append(plain, byte(i*29+j*13+5))
		}
	}
	got := make(chan []byte, 1)
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		b := make([]byte, len(plain))
		_, e := io.ReadFull(c, b)
		if e != nil {
			got <- nil
			return
		}
		got <- b
		c.Write([]byte("ok"))
	})
	s := startTest(t, ssIn(), nil)
	salt := bytes.Repeat([]byte{0x6d}, 16)
	a := deriveTest(t, key2022(), salt)
	variable := append(peerAddr(target, false), 0, 1, 0)
	fixed := []byte{0}
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))
	nonce := make([]byte, 12)
	wire := append(append([]byte(nil), salt...), a.Seal(nil, nonce, fixed, nil)...)
	next := func() []byte {
		nonce[0]++
		return nonce
	}
	wire = append(wire, a.Seal(nil, next(), variable, nil)...)
	off := 0
	for _, n := range sizes {
		wire = append(wire, a.Seal(nil, next(), binary.BigEndian.AppendUint16(nil, uint16(n)), nil)...)
		wire = append(wire, a.Seal(nil, next(), plain[off:off+n], nil)...)
		off += n
	}
	c := dialPeer(t, s, nil)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if e := writeAll(c, wire); e != nil {
		t.Fatal(e)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, plain) {
			t.Fatal("target did not receive the exact upload")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("upload did not reach the target")
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
}
