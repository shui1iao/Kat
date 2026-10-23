package ss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWrite2022BufferWireEquivalent(t *testing.T) {
	for _, method := range methods[3:] {
		t.Run(method, func(t *testing.T) {
			srv := server(t, method)
			a, _ := srv.aead(seq(0x64, srv.m.keySize))
			for _, size := range []int{1, 1023, 1024, 16384, 65501, 65535} {
				plain := bytes.Repeat([]byte{0x5e}, size)
				got := &memTransport{}
				want := &memTransport{}
				c := &TCPConn{server: srv, transport: got, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
				ref := &TCPConn{server: srv, transport: want, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
				wire := make([]byte, 34+size)
				copy(wire[18:], plain)
				n, err := c.Write2022Buffers([][]byte{wire})
				rn, re := ref.Write(plain)
				if n != rn || err != re || !bytes.Equal(got.output.Bytes(), want.output.Bytes()) || c.writeNonce != ref.writeNonce {
					t.Fatal(size, n, err, rn, re)
				}
			}
		})
	}
}
func TestWrite2022BufferLazyResponseAndErrors(t *testing.T) {
	for _, method := range methods[3:] {
		srv := server(t, method)
		request := tcpRequest(t, srv, seq(0x34, srv.m.keySize), uint64(testTime.Unix()), testTarget, 1, nil, nil)
		tr := &memTransport{input: bytes.NewReader(request)}
		c, err := srv.Accept(tr)
		if err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 34+2048)
		copy(wire[18:], bytes.Repeat([]byte{0x69}, 2048))
		if n, e := c.Write2022Buffers([][]byte{wire}); n != 2048 || e != nil {
			t.Fatal(n, e)
		}
		if !bytes.Equal(wire[18:18+2048], bytes.Repeat([]byte{0x69}, 2048)) {
			t.Fatal("lazy fallback mutated plaintext")
		}
		// Independently open the lazy response header+payload.
		r := bytes.NewReader(tr.output.Bytes())
		salt := make([]byte, srv.m.keySize)
		io.ReadFull(r, salt)
		a, _ := srv.aead(salt)
		var nonce counter
		h := make([]byte, 1+8+srv.m.keySize+2+16)
		io.ReadFull(r, h)
		header, e := open(a, &nonce, h)
		if e != nil || header[0] != 1 || !bytes.Equal(header[9:9+srv.m.keySize], c.requestSalt) || binary.BigEndian.Uint16(header[len(header)-2:]) != 2048 {
			t.Fatal("lazy response header", e)
		}
		b := make([]byte, 2048+16)
		io.ReadFull(r, b)
		p, e := open(a, &nonce, b)
		if e != nil || !bytes.Equal(p, wire[18:18+2048]) {
			t.Fatal("lazy body", e)
		}
		c.writeNonce.exhausted = true
		if _, e = c.Write2022Buffers([][]byte{wire}); !errors.Is(e, ErrNonceExhausted) {
			t.Fatal(e)
		}
		if _, e = c.Write2022Buffers([][]byte{wire}); !errors.Is(e, ErrNonceExhausted) {
			t.Fatal("non-sticky", e)
		}
	}
}

func TestWrite2022BuffersPrefixNonceAndTransportFailure(t *testing.T) {
	for _, method := range methods[3:] {
		srv := server(t, method)
		a, _ := srv.aead(seq(0x63, srv.m.keySize))
		plain := bytes.Repeat([]byte{0x55}, 2048)
		wires := func() [][]byte {
			var out [][]byte
			for i := 0; i < 2; i++ {
				b := make([]byte, 34+len(plain))
				copy(b[18:], plain)
				out = append(out, b)
			}
			return out
		}
		tr := &memTransport{}
		reftr := &memTransport{}
		c := &TCPConn{server: srv, transport: tr, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
		ref := &TCPConn{server: srv, transport: reftr, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
		for i := range c.writeNonce.value {
			c.writeNonce.value[i] = 0xff
		}
		c.writeNonce.value[0] = 0xfd
		ref.writeNonce = c.writeNonce
		n, e := c.Write2022Buffers(wires())
		ref.Write(plain)
		_, re := ref.Write(plain)
		if n != len(plain) || e != ErrNonceExhausted || re != e || !bytes.Equal(tr.output.Bytes(), reftr.output.Bytes()) {
			t.Fatal(method, n, e, re)
		}
		if _, e = c.Write2022Buffers(wires()); e != ErrNonceExhausted {
			t.Fatal("nonce error not sticky", e)
		}
		fail := &write2022FailTransport{}
		c = &TCPConn{server: srv, transport: fail, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
		if n, e = c.Write2022Buffers(wires()); n != 0 || e != io.ErrClosedPipe {
			t.Fatal(method, n, e)
		}
		if _, e = c.Write2022Buffers(wires()); e != io.ErrClosedPipe || fail.writes != 1 {
			t.Fatal("transport error not sticky", e)
		}
	}
}

type write2022FailTransport struct{ writes int }

func (t *write2022FailTransport) Read(p []byte) (int, error)  { return 0, io.EOF }
func (t *write2022FailTransport) Write(p []byte) (int, error) { t.writes++; return 0, io.ErrClosedPipe }
func (t *write2022FailTransport) Close() error                { return nil }

func TestWrite2022BuffersRealTCP(t *testing.T) {
	for _, method := range methods[3:] {
		srv := server(t, method)
		a, _ := srv.aead(seq(0x61, srv.m.keySize))
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		accepted := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); accepted <- c }()
		dst, e := net.Dial("tcp4", ln.Addr().String())
		if e != nil {
			ln.Close()
			<-accepted
			t.Fatal(e)
		}
		peer := <-accepted
		ln.Close()
		dst.SetDeadline(time.Now().Add(time.Second))
		peer.SetDeadline(time.Now().Add(time.Second))
		var wires [][]byte
		var expected bytes.Buffer
		reftr := &memTransport{}
		ref := &TCPConn{server: srv, transport: reftr, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
		total := 0
		for _, size := range []int{65535, 1, 32768, 1023, 1024, 65535, 1, 19} {
			b := make([]byte, 34+size)
			for i := 18; i < len(b)-16; i++ {
				b[i] = byte(i*7 + size)
			}
			ref.Write(b[18 : len(b)-16])
			wires = append(wires, b)
			total += size
		}
		expected.Write(reftr.output.Bytes())
		c := &TCPConn{server: srv, transport: dst, reader: recordReader{max: MaxChunk2022}, writerAEAD: a}
		received := make(chan []byte, 1)
		go func() {
			p := make([]byte, expected.Len())
			if _, e := io.ReadFull(peer, p); e != nil {
				received <- nil
			} else {
				received <- p
			}
		}()
		n, e := c.Write2022Buffers(wires)
		got := <-received
		dst.Close()
		peer.Close()
		if n != total || e != nil || !bytes.Equal(got, expected.Bytes()) {
			t.Fatal(method, n, e, "wire differs")
		}
	}
}
