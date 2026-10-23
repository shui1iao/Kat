package vlessx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type memoryConn struct {
	*bytes.Reader
	out    bytes.Buffer
	closed bool
}

func (m *memoryConn) Write(p []byte) (int, error)      { return m.out.Write(p) }
func (m *memoryConn) Close() error                     { m.closed = true; return nil }
func (m *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (m *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (m *memoryConn) SetDeadline(time.Time) error      { return nil }
func (m *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memoryConn) SetWriteDeadline(time.Time) error { return nil }
func reqWire(q Request) []byte {
	b := append([]byte{0}, q.UUID[:]...)
	addons := []byte{}
	if q.Flow != "" {
		addons = append([]byte{10, byte(len(q.Flow))}, q.Flow...)
	}
	b = append(b, byte(len(addons)))
	b = append(b, addons...)
	b = append(b, q.Command)
	if q.Command == 1 || q.Command == 2 {
		a, _ := encodeAddress(q.Target)
		b = append(b, a...)
	}
	return b
}
func TestHeaderAddonsAndFlowPolicy(t *testing.T) {
	for _, q := range []Request{{UUID: testID, Command: 1, Target: Address{"example.test", 443}, Flow: VisionFlow}, {UUID: testID, Command: 3}} {
		b := reqWire(q)
		got, e := ReadRequest(bytes.NewReader(b), func(q Request) bool { return q.UUID == testID })
		must(t, e)
		if got.UUID != q.UUID || got.Command != q.Command || got.Target != q.Target || got.Flow != q.Flow {
			t.Fatal(got)
		}
	}
	b := reqWire(Request{UUID: testID, Command: 1, Target: Address{"127.0.0.1", 80}, Flow: VisionFlow})
	if _, e := ReadRequest(bytes.NewReader(b), func(Request) bool { return false }); e != ErrState {
		t.Fatal(e)
	}
	for i := 0; i < len(b); i++ {
		if _, e := ReadRequest(bytes.NewReader(b[:i]), func(Request) bool { return true }); e == nil {
			t.Fatal("truncation accepted", i)
		}
	}
	for _, q := range []Request{{UUID: testID, Command: 4}, {UUID: testID, Command: 7}, {UUID: testID, Command: 2, Flow: VisionFlow, Target: Address{"::1", 443}}, {UUID: testID, Command: 3, Flow: "xtls-rprx-vision-udp443"}} {
		if _, e := ReadRequest(bytes.NewReader(reqWire(q)), func(Request) bool { return true }); e == nil {
			t.Fatal(q)
		}
	}
	flow, seed, e := ParseAddons([]byte{0x78, 1, 10, 1, 120, 0x12, 2, 3, 4, 0x85, 1, 0, 0, 0, 0})
	must(t, e)
	if flow != "x" || !bytes.Equal(seed, []byte{3, 4}) {
		t.Fatal(flow, seed)
	}
	for _, b := range [][]byte{{0}, {10, 255}, {0x80}, {0x0b}, {9, 1}, {0x12, 2, 1}} {
		if _, _, e := ParseAddons(b); e == nil {
			t.Fatal(b)
		}
	}
}
func muxFrame(id uint16, status, opt byte, target *Address, tail, data []byte) []byte {
	h := []byte{byte(id >> 8), byte(id), status, opt}
	if target != nil {
		addr, _ := encodeAddress(*target)
		h = append(h, 2)
		h = append(h, addr...)
	}
	h = append(h, tail...)
	b := []byte{byte(len(h) >> 8), byte(len(h))}
	b = append(b, h...)
	if opt&1 != 0 {
		b = append(b, byte(len(data)>>8), byte(len(data)))
		b = append(b, data...)
	}
	return b
}
func TestMuxSessionsAddressBoundariesAndStaleReplies(t *testing.T) {
	a, b, c := Address{"127.0.0.1", 30001}, Address{"::1", 30002}, Address{"dns.example", 30003}
	var wire []byte
	global := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	wire = append(wire, muxFrame(0, 1, 1, &a, global, []byte("first"))...)
	wire = append(wire, muxFrame(0, 2, 1, &b, nil, []byte("second"))...)
	wire = append(wire, muxFrame(1, 1, 1, &c, nil, nil)...)
	wire = append(wire, muxFrame(0, 3, 0, nil, nil, nil)...)
	wire = append(wire, muxFrame(0, 1, 1, &a, nil, []byte("new generation"))...)
	m := &memoryConn{Reader: bytes.NewReader(wire)}
	mux, e := NewMux(m, 2)
	must(t, e)
	d, e := mux.ReadDatagram()
	must(t, e)
	if d.Target != a || string(d.Payload) != "first" || d.GlobalID != [8]byte{1, 2, 3, 4, 5, 6, 7, 8} {
		t.Fatal(d)
	}
	old := d
	must(t, mux.Reply(d, a, []byte("reply")))
	d, e = mux.ReadDatagram()
	must(t, e)
	if d.Target != b || string(d.Payload) != "second" {
		t.Fatal(d)
	}
	d, e = mux.ReadDatagram()
	must(t, e)
	if d.Target != c || len(d.Payload) != 0 {
		t.Fatal(d)
	}
	d, e = mux.ReadDatagram()
	must(t, e)
	if d.Generation == old.Generation {
		t.Fatal("stale generation")
	}
	if e = mux.Reply(old, a, nil); e != ErrState {
		t.Fatal(e)
	}
	if e = mux.Reply(d, a, make([]byte, 8193)); e != ErrLimit {
		t.Fatal(e)
	}
	must(t, mux.End(0))
	if e = mux.Reply(d, a, nil); e != ErrState {
		t.Fatal(e)
	}
	must(t, mux.Close())
	if !m.closed {
		t.Fatal("not closed")
	}
}
func TestMuxMaliciousFrames(t *testing.T) {
	a := Address{"127.0.0.1", 53}
	bad := [][]byte{{0, 3, 0, 0, 0}, {2, 1}, muxFrame(1, 2, 1, nil, nil, []byte{1}), muxFrame(1, 5, 0, nil, nil, nil), muxFrame(1, 1, 4, &a, nil, nil), muxFrame(1, 1, 0, &a, []byte{1}, nil), muxFrame(1, 1, 1, &a, nil, make([]byte, 8193)), muxFrame(1, 3, 0, nil, nil, nil)}
	tcp := muxFrame(1, 1, 1, &a, nil, []byte{1})
	tcp[6] = 1
	bad = append(bad, tcp)
	dup := muxFrame(0, 1, 1, &a, nil, []byte{1})
	bad = append(bad, append(bytes.Clone(dup), dup...))
	for i, b := range bad {
		m := &memoryConn{Reader: bytes.NewReader(b)}
		mux, e := NewMux(m, 1)
		must(t, e)
		_, e = mux.ReadDatagram()
		if i == len(bad)-1 && e == nil {
			_, e = mux.ReadDatagram()
		}
		if e == nil {
			t.Fatal("accepted bad frame", i)
		}
	}
	frames := append(muxFrame(0, 1, 1, &a, nil, []byte{1}), muxFrame(1, 1, 1, &a, nil, []byte{2})...)
	mux, _ := NewMux(&memoryConn{Reader: bytes.NewReader(frames)}, 1)
	_, e := mux.ReadDatagram()
	must(t, e)
	if _, e = mux.ReadDatagram(); e != ErrLimit {
		t.Fatal(e)
	}
	var controls []byte
	for i := 0; i < 128; i++ {
		controls = append(controls, muxFrame(0, 4, 0, nil, nil, nil)...)
	}
	mux, _ = NewMux(&memoryConn{Reader: bytes.NewReader(controls)}, 1)
	if _, e = mux.ReadDatagram(); e != ErrLimit {
		t.Fatal(e)
	}
}
func tlsRecord(kind byte, p []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(p) >> 8), byte(len(p))}, p...)
}
func clientHelloFixture() []byte {
	b := make([]byte, 35)
	b[0] = 3
	b[1] = 3
	b = append(b, 0, 2, 0x13, 1, 1, 0, 0, 0)
	h := []byte{1, 0, 0, byte(len(b))}
	return tlsRecord(22, append(h, b...))
}
func serverHelloFixture(version uint16, cipher uint16) []byte {
	b := make([]byte, 40)
	b[0] = 3
	b[1] = 3
	b[34] = 0
	binary.BigEndian.PutUint16(b[35:37], cipher)
	b[37] = 0
	binary.BigEndian.PutUint16(b[38:40], 6)
	b = append(b, 0, 43, 0, 2, byte(version>>8), byte(version))
	h := []byte{2, 0, 0, byte(len(b))}
	return tlsRecord(22, append(h, b...))
}
func TestVisionTLSRecognitionFragments(t *testing.T) {
	for _, v := range []uint16{0x303, 0x304} {
		for _, cipher := range []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305} {
			s := new(visionTLS)
			ch := clientHelloFixture()
			for _, b := range ch {
				s.feed(true, []byte{b})
			}
			sh := serverHelloFixture(v, cipher)
			for _, b := range sh {
				s.feed(false, []byte{b})
			}
			if s.canDirect() != (v == 0x304 && cipher <= 0x1304) {
				t.Fatal(v, cipher)
			}
			ok, app, _ := s.feed(false, tlsRecord(23, []byte("encrypted-inner")))
			if !ok || !app {
				t.Fatal("app boundary")
			}
		}
	}
	s := new(visionTLS)
	s.feed(true, clientHelloFixture())
	s.feed(true, serverHelloFixture(0x304, 0x1301))
	if s.canDirect() {
		t.Fatal("client-supplied server hello enabled direct")
	}
	s = new(visionTLS)
	b := serverHelloFixture(0x304, 0x1301)
	s.feed(false, b)
	if s.canDirect() {
		t.Fatal("no client hello")
	}
	s.feed(true, []byte("GET / HTTP/1.1\r\n\r\n"))
	if s.canDirect() {
		t.Fatal("nonTLS")
	}
}
func visionFrame(id *[16]byte, cmd byte, p []byte, pad int) []byte {
	b := []byte{}
	if id != nil {
		b = append(b, id[:]...)
	}
	b = append(b, cmd, byte(len(p)>>8), byte(len(p)), byte(pad>>8), byte(pad))
	b = append(b, p...)
	return append(b, make([]byte, pad)...)
}

// A lightweight test transport uses ordinary memory I/O; no direct switch can
// succeed without the full outer TLS gate invariant (tested separately live).
func TestVisionPaddingFragmentationAndCommands(t *testing.T) {
	frames := append(visionFrame(&testID, 0, []byte("part1"), 31), visionFrame(nil, 1, []byte("part2"), 0)...)
	frames = append(frames, []byte("tail")...)
	m := &memoryConn{Reader: bytes.NewReader(frames)}
	owned := &ownedConn{Conn: m, done: make(chan struct{})}
	tr := &Transport{secure: m, gate: &recordGate{ownedConn: owned}}
	v := &Vision{transport: tr, uuid: testID, firstRead: true}
	var got bytes.Buffer
	b := make([]byte, 1)
	for {
		n, e := v.Read(b)
		got.Write(b[:n])
		if e == io.EOF {
			break
		}
		must(t, e)
	}
	if got.String() != "part1part2tail" {
		t.Fatal(got.String())
	}
	for _, wire := range [][]byte{visionFrame(&testID, 3, nil, 0), visionFrame(&testID, 0, nil, 8193), visionFrame(&testID, 2, tlsRecord(23, []byte{1}), 0)} {
		m := &memoryConn{Reader: bytes.NewReader(wire)}
		own := &ownedConn{Conn: m, done: make(chan struct{})}
		tr := &Transport{secure: m, gate: &recordGate{ownedConn: own}}
		v := &Vision{transport: tr, uuid: testID, firstRead: true}
		if _, e := v.Read(make([]byte, 100)); e == nil {
			t.Fatal("invalid vision accepted")
		}
	}
}
func TestPublicTLSGateMergedRawAndHalfClose(t *testing.T) {
	cert := certFor(t, "front.test")
	ln := tcpListen(t)
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		tr, e := AcceptTLS(context.Background(), c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		if e != nil {
			done <- e
			return
		}
		defer tr.Close()
		tr.SetDeadline(time.Now().Add(3 * time.Second))
		p := make([]byte, 3)
		_, e = io.ReadFull(tr, p)
		if e != nil {
			done <- e
			return
		}
		if string(p) != "one" {
			done <- ErrWire
			return
		}
		if e = tr.switchRead(); e != nil {
			done <- e
			return
		}
		got, e := io.ReadAll(tr)
		if e != nil {
			done <- e
			return
		}
		if string(got) != "TLS-cache-then-raw-bytes" {
			done <- ErrWire
			return
		}
		e = writeFull(tr, []byte("reply"))
		if e == nil {
			e = tr.CloseWrite()
		}
		done <- e
	}()
	raw, e := net.Dial("tcp", ln.Addr().String())
	must(t, e)
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{RootCAs: certRoots(t, cert), ServerName: "front.test", MinVersion: tls.VersionTLS13})
	must(t, tc.Handshake())
	must(t, writeFull(tc, []byte("oneTLS-cache-then-")))
	must(t, writeFull(raw, []byte("raw-bytes")))
	must(t, raw.(*net.TCPConn).CloseWrite())
	b, e := io.ReadAll(tc)
	must(t, e)
	if string(b) != "reply" {
		t.Fatal(string(b))
	}
	must(t, <-done)
}
func TestTransportCancelDeadlineAndInvalidGate(t *testing.T) {
	cert := certFor(t, "front.test")
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := AcceptTLS(ctx, a, &tls.Config{Certificates: []tls.Certificate{cert}}); done <- e }()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("accepted canceled")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel stuck")
	}
	m := &memoryConn{Reader: bytes.NewReader([]byte{23, 3, 3, 255, 255})}
	g := &recordGate{ownedConn: &ownedConn{Conn: m, done: make(chan struct{})}}
	if _, e := g.Read(make([]byte, 100)); e != ErrLimit {
		t.Fatal(e)
	}
	g.remaining = 1
	tr := &Transport{gate: g}
	if e := tr.switchRead(); e != ErrState {
		t.Fatal(e)
	}
	g.remaining = 0
	must(t, tr.switchWrite())
	if _, e := g.Write([]byte{1}); !errors.Is(e, ErrState) || !m.closed {
		t.Fatal(e)
	}
}

func TestMuxSlowConsumerCloseInterruptsReply(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	mux, e := NewMux(a, 1)
	must(t, e)
	target := Address{"127.0.0.1", 1234}
	sender := make(chan error, 1)
	go func() { sender <- writeFull(b, muxFrame(0, 1, 1, &target, nil, []byte{1})) }()
	d, e := mux.ReadDatagram()
	must(t, e)
	must(t, <-sender)
	replyDone := make(chan error, 1)
	go func() { replyDone <- mux.Reply(d, target, make([]byte, 8192)) }()
	time.Sleep(10 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- mux.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind slow writer")
	}
	select {
	case e := <-replyDone:
		if e == nil {
			t.Fatal("unexpected successful blocked write")
		}
	case <-time.After(time.Second):
		t.Fatal("writer not interrupted")
	}
}

func TestVisionBadUUIDTruncationAndZeroBudget(t *testing.T) {
	valid := visionFrame(&testID, 1, []byte("content"), 35)
	for i := 0; i < len(valid); i++ {
		m := &memoryConn{Reader: bytes.NewReader(valid[:i])}
		own := &ownedConn{Conn: m, done: make(chan struct{})}
		v := &Vision{transport: &Transport{secure: m, gate: &recordGate{ownedConn: own}}, uuid: testID, firstRead: true}
		if _, e := v.Read(make([]byte, 100)); e == nil {
			t.Fatal("truncated accepted", i)
		}
	}
	bad := bytes.Clone(valid)
	bad[0] ^= 1
	var frames []byte
	frames = append(frames, visionFrame(&testID, 0, nil, 0)...)
	for i := 0; i < 64; i++ {
		frames = append(frames, visionFrame(nil, 0, nil, 0)...)
	}
	for _, b := range [][]byte{bad, frames} {
		m := &memoryConn{Reader: bytes.NewReader(b)}
		own := &ownedConn{Conn: m, done: make(chan struct{})}
		v := &Vision{transport: &Transport{secure: m, gate: &recordGate{ownedConn: own}}, uuid: testID, firstRead: true}
		if _, e := v.Read(make([]byte, 10)); e == nil || !m.closed {
			t.Fatal("accepted bad UUID/unbounded zero frames", e)
		}
	}
}
func TestTLSBadAuthenticationAndActiveCancel(t *testing.T) {
	cert := certFor(t, "front.test")
	for _, badTag := range []bool{false, true} {
		ln := tcpListen(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		ready := make(chan struct{})
		go func() {
			c, e := ln.Accept()
			if e != nil {
				done <- e
				return
			}
			tr, e := AcceptTLS(ctx, c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
			if e != nil {
				done <- e
				return
			}
			defer tr.Close()
			close(ready)
			var b [32]byte
			_, e = tr.Read(b[:])
			done <- e
		}()
		raw, e := net.Dial("tcp", ln.Addr().String())
		must(t, e)
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		cc := tls.Client(raw, &tls.Config{RootCAs: certRoots(t, cert), ServerName: "front.test", MinVersion: tls.VersionTLS13})
		must(t, cc.Handshake())
		<-ready
		if badTag {
			must(t, writeFull(raw, append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...)))
		} else {
			cancel()
		}
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("bad tag/cancel accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("blocked")
		}
		cancel()
		raw.Close()
		ln.Close()
	}
}

func TestFinalTLSRecordGateAtomicity(t *testing.T) {
	for _, insertKU := range []bool{false, true} {
		m := &memoryConn{Reader: bytes.NewReader(nil)}
		g := &recordGate{ownedConn: &ownedConn{Conn: m, done: make(chan struct{})}, finalRecordBytes: 122}
		if insertKU {
			ku := append([]byte{23, 3, 3, 0, 22}, make([]byte, 22)...)
			if _, e := g.Write(ku); e != ErrState || !m.closed || m.out.Len() != 0 {
				t.Fatal("KeyUpdate-like write was allowed in final-record window", e)
			}
			continue
		}
		final := append([]byte{23, 3, 3, 0, 117}, make([]byte, 117)...)
		n, e := g.Write(final)
		must(t, e)
		if n != 122 || !g.writeDirect || g.finalRecordBytes != 0 {
			t.Fatal("final record not atomic")
		}
		if _, e = g.Write([]byte{23, 3, 3, 0, 22}); e != ErrState || m.out.Len() != 122 {
			t.Fatal("TLS write allowed after final record")
		}
	}
}
