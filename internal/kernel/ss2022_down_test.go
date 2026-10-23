package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ss2022DownBuf is a test-only target double whose socket readiness is not a
// kernel socket (no coalescing) and whose reads/writes are recorded.
type ss2022DownBuf struct {
	net.Conn
	r      io.Reader
	w      io.Writer
	writes []int
	half   int
}

func (c *ss2022DownBuf) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *ss2022DownBuf) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return c.w.Write(p)
}
func (c *ss2022DownBuf) CloseWrite() error { c.half++; return nil }

type ss2022DownErrReader struct{ done bool }

func (r *ss2022DownErrReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, "tail"), errors.New("boom")
}

func TestSS2022DownOnlySS2022Wrapped(t *testing.T) {
	out, _ := ss2017TCPPair(t)
	v2017 := startTest(t, Inbound{Protocol: "shadowsocks", SS: &SSOptions{Method: "aes-128-gcm", Password: "down-2022-fixture", Salts2017: 16}}, nil)
	v2022 := startTest(t, ssIn(), nil)
	socks := startTest(t, inFor("socks5", nil), nil)
	in2017, in2022, inSocks := v2017.cfg.Inbounds[0], v2022.cfg.Inbounds[0], socks.cfg.Inbounds[0]
	w, ok := ss2022DownTarget(in2022, out).(*ss2022DownConn)
	if !ok || w.Conn != net.Conn(out) {
		t.Fatal("SS2022 target not wrapped")
	}
	for _, in := range []Inbound{in2017, inSocks} {
		if got := ss2022DownTarget(in, out); got != net.Conn(out) {
			t.Fatalf("protocol %s target wrapped by SS2022 download", in.Protocol)
		}
	}
	// SS2017 keeps exactly its own read view wrapper.
	if _, ok := ss2022DownTarget(in2017, ssDownTarget(in2017, out)).(*ssDownReadConn); !ok {
		t.Fatal("SS2017 wrapper changed")
	}
}

func TestSS2022DownCopyOnlyTargetToClient(t *testing.T) {
	payload := bytes.Repeat([]byte("ss2022-down-"), 20000)
	for _, idle := range []bool{false, true} {
		s := &Server{pool: newBufferPool(16384, 2)}
		target := &ss2022DownConn{&ss2022DownBuf{r: bytes.NewReader(payload)}}
		var out bytes.Buffer
		client := &ss2022DownBuf{w: &out}
		var src net.Conn = target
		if idle {
			src = &activityStream{target, new(atomic.Int64)}
		}
		if _, ok := ss2022DownSource(src); !ok {
			t.Fatal("download source not recognised")
		}
		if _, ok := ss2022DownSource(client); ok {
			t.Fatal("client side recognised as SS2022 target")
		}
		if e := s.copy(client, src); e != nil || !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("idle=%v copy e=%v got=%d", idle, e, out.Len())
		}
		for _, n := range client.writes {
			if n > 16384 {
				t.Fatalf("non-socket target coalesced a %dB write", n)
			}
		}
	}
}

func TestSS2022DownDataWithErrorAndHalfClose(t *testing.T) {
	s := &Server{pool: newBufferPool(16384, 1)}
	var out bytes.Buffer
	target := &ss2022DownConn{&ss2022DownBuf{r: &ss2022DownErrReader{}}}
	e := s.copy(&ss2022DownBuf{w: &out}, target)
	if e == nil || e.Error() != "boom" || out.String() != "tail" {
		t.Fatalf("data+error e=%v out=%q", e, out.String())
	}
	inner := &ss2022DownBuf{}
	if (&ss2022DownConn{inner}).CloseWrite() != nil || inner.half != 1 {
		t.Fatal("half-close not forwarded")
	}
}

func TestSS2022DownLeaseBoundedAndCleared(t *testing.T) {
	var held [][]byte
	for i := 0; i < ss2022DownLeases; i++ {
		b := leaseSS2022Down()
		if b == nil || len(b) != ss2022DownLeaseBytes {
			t.Fatalf("lease %d = %d", i, len(b))
		}
		b[0], b[len(b)-1] = 1, 1
		held = append(held, b)
	}
	if leaseSS2022Down() != nil {
		t.Fatal("lease above the bound")
	}
	for _, b := range held {
		releaseSS2022Down(b)
		if b[0] != 0 || b[len(b)-1] != 0 {
			t.Fatal("lease not cleared on release")
		}
	}
	b := leaseSS2022Down()
	if b == nil {
		t.Fatal("lease not returned")
	}
	for _, x := range b {
		if x != 0 {
			t.Fatal("reused lease not clear")
		}
	}
	releaseSS2022Down(b)
}

// End to end: a real target socket sends 512KiB at once; the client decodes the
// SS2022 response independently. Payload must be exact, every record within
// ss.MaxChunk2022, and the already-queued bytes must coalesce beyond 16384.
func TestSS2022DownKernelRelayCoalesces(t *testing.T) {
	data := make([]byte, 512*1024)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		b := make([]byte, 7)
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		c.Write(data)
		c.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, c)
	})
	s := startTest(t, ssIn(), nil)
	salt := bytes.Repeat([]byte{0x5e}, 16)
	a := deriveTest(t, key2022(), salt)
	variable := append(peerAddr(target, false), 0, 0, 7)
	variable = append(variable, []byte("request")...)
	fixed := []byte{0}
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))
	nonce := make([]byte, 12)
	wire := append(append([]byte(nil), salt...), a.Seal(nil, nonce, fixed, nil)...)
	nonce[0]++
	wire = append(wire, a.Seal(nil, nonce, variable, nil)...)
	c := dialPeer(t, s, nil)
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if e := writeAll(c, wire); e != nil {
		t.Fatal(e)
	}
	time.Sleep(100 * time.Millisecond)
	rsalt := make([]byte, 16)
	if _, e := io.ReadFull(c, rsalt); e != nil {
		t.Fatal(e)
	}
	r := deriveTest(t, key2022(), rsalt)
	rn := make([]byte, 12)
	step := func() []byte {
		b := append([]byte(nil), rn...)
		binary.LittleEndian.PutUint64(rn, binary.LittleEndian.Uint64(rn)+1)
		return b
	}
	h := make([]byte, 1+8+16+2+16)
	if _, e := io.ReadFull(c, h); e != nil {
		t.Fatal(e)
	}
	hp, e := r.Open(nil, step(), h, nil)
	if e != nil || hp[0] != 1 || !bytes.Equal(hp[9:25], salt) {
		t.Fatalf("response header e=%v", e)
	}
	n := int(binary.BigEndian.Uint16(hp[25:27]))
	var got []byte
	largest := 0
	for {
		body := make([]byte, n+16)
		if _, e := io.ReadFull(c, body); e != nil {
			t.Fatal(e)
		}
		p, e := r.Open(nil, step(), body, nil)
		if e != nil {
			t.Fatal("record auth", e)
		}
		got = append(got, p...)
		largest = max(largest, len(p))
		if len(p) > ss.MaxChunk2022 {
			t.Fatalf("record %d > MaxChunk2022", len(p))
		}
		if len(got) >= len(data) {
			break
		}
		lh := make([]byte, 2+16)
		if _, e := io.ReadFull(c, lh); e != nil {
			t.Fatal(e)
		}
		lp, e := r.Open(nil, step(), lh, nil)
		if e != nil {
			t.Fatal(e)
		}
		n = int(binary.BigEndian.Uint16(lp))
	}
	if !bytes.Equal(got, data) {
		t.Fatal("download payload differs")
	}
	if largest <= 16384 {
		t.Fatalf("no coalesced record (largest %d)", largest)
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
}
