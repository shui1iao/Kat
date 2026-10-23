package kernel

import (
	"bytes"
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"testing"
	"time"
)

// ss2017DownConn is a test-only target double: it records every read view the
// wrapper hands down, every write it receives, half-close and deadlines.
type ss2017DownConn struct {
	net.Conn
	r         io.Reader
	w         io.Writer
	views     [][]byte
	writes    []int
	halfClose int
	deadline  [3]time.Time
}

func (c *ss2017DownConn) Read(p []byte) (int, error) {
	c.views = append(c.views, p)
	return c.r.Read(p)
}

func (c *ss2017DownConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return c.w.Write(p)
}

func (c *ss2017DownConn) CloseWrite() error {
	c.halfClose++
	return nil
}

func (c *ss2017DownConn) SetDeadline(t time.Time) error {
	c.deadline[0] = t
	return nil
}

func (c *ss2017DownConn) SetReadDeadline(t time.Time) error {
	c.deadline[1] = t
	return nil
}

func (c *ss2017DownConn) SetWriteDeadline(t time.Time) error {
	c.deadline[2] = t
	return nil
}

type ss2017ShortReader struct{ r io.Reader }

func (s ss2017ShortReader) Read(p []byte) (int, error) {
	return s.r.Read(p[:min(len(p), 7)])
}

type ss2017DataErrReader struct {
	done bool
	err  error
}

func (r *ss2017DataErrReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, "tail"), r.err
}

func ss2017TCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, e := net.Dial("tcp4", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	server := <-accepted
	if server == nil {
		client.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func TestSS2017DownReadCapOriginalBacking(t *testing.T) {
	if ss.MaxChunk2017 != 16383 {
		t.Fatalf("MaxChunk2017=%d", ss.MaxChunk2017)
	}
	for _, size := range []int{1024, 16384, 65536} {
		want := min(size, ss.MaxChunk2017)
		direct := &ss2017DownConn{r: bytes.NewReader(make([]byte, size))}
		buf := make([]byte, size)
		n, e := (&ssDownReadConn{direct}).Read(buf)
		v := direct.views[0]
		if e != nil || n != want || len(v) != want || cap(v) != size || &v[0] != &buf[0] {
			t.Fatalf("size=%d direct n=%d len=%d cap=%d", size, n, len(v), cap(v))
		}
		total := 3 * size
		payload := make([]byte, total)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		base := make([]byte, size)
		s := &Server{pool: newBufferPool(size, 1)}
		s.pool.free <- base
		src := &ss2017DownConn{r: bytes.NewReader(payload)}
		var out bytes.Buffer
		if e := s.copy(&ss2017DownConn{w: &out}, &ssDownReadConn{src}); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("size=%d payload mismatch got=%d", size, out.Len())
		}
		for _, v := range src.views {
			if len(v) != want || cap(v) != size || &v[0] != &base[0] {
				t.Fatalf("size=%d view len=%d cap=%d is not the original pool backing", size, len(v), cap(v))
			}
		}
	}
}

func TestSS2017DownShortRead(t *testing.T) {
	c := &ss2017DownConn{r: ss2017ShortReader{bytes.NewReader(make([]byte, 100))}}
	n, e := (&ssDownReadConn{c}).Read(make([]byte, 65536))
	if e != nil || n != 7 || len(c.views[0]) != ss.MaxChunk2017 {
		t.Fatalf("short read n=%d e=%v", n, e)
	}
	payload := bytes.Repeat([]byte("short-read-"), 9000)
	s := &Server{pool: newBufferPool(16384, 1)}
	src := &ss2017DownConn{r: ss2017ShortReader{bytes.NewReader(payload)}}
	var out bytes.Buffer
	if e := s.copy(&ss2017DownConn{w: &out}, &ssDownReadConn{src}); e != nil || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("short-read copy e=%v got=%d", e, out.Len())
	}
}

func TestSS2017DownPoolFullCapCleared(t *testing.T) {
	for _, size := range []int{16384, 65536} {
		base := make([]byte, size)
		s := &Server{pool: newBufferPool(size, 1)}
		s.pool.free <- base
		payload := bytes.Repeat([]byte{0xa5}, 40000)
		var out bytes.Buffer
		src := &ssDownReadConn{&ss2017DownConn{r: bytes.NewReader(payload)}}
		if e := s.copy(&ss2017DownConn{w: &out}, src); e != nil || !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("size=%d copy e=%v", size, e)
		}
		select {
		case b := <-s.pool.free:
			if len(b) != size || cap(b) != size || &b[0] != &base[0] || !bytes.Equal(b, make([]byte, size)) {
				t.Fatalf("size=%d pool got len=%d cap=%d, not the full cleared original", size, len(b), cap(b))
			}
		default:
			t.Fatalf("size=%d original buffer not returned to pool", size)
		}
	}
}

func TestSS2017DownReadDataWithError(t *testing.T) {
	boom := errors.New("target read error with data")
	for _, want := range []error{boom, io.EOF} {
		r := &ss2017DataErrReader{err: want}
		n, e := (&ssDownReadConn{&ss2017DownConn{r: r}}).Read(make([]byte, 16384))
		if n != 4 || e != want {
			t.Fatalf("direct n=%d e=%v want %v", n, e, want)
		}
		var out bytes.Buffer
		s := &Server{pool: newBufferPool(16384, 1)}
		e = s.copy(&ss2017DownConn{w: &out}, &ssDownReadConn{&ss2017DownConn{r: &ss2017DataErrReader{err: want}}})
		if out.String() != "tail" {
			t.Fatalf("data before error lost: %q", out.String())
		}
		if want == io.EOF {
			if e != nil {
				t.Fatalf("EOF with data must end the copy cleanly: %v", e)
			}
		} else if !errors.Is(e, boom) {
			t.Fatalf("error with data not propagated: %v", e)
		}
	}
}

func TestSS2017DownReverseWriteUncapped(t *testing.T) {
	var sent bytes.Buffer
	c := &ss2017DownConn{w: &sent}
	payload := bytes.Repeat([]byte{0x33}, 65536)
	n, e := (&ssDownReadConn{c}).Write(payload)
	if e != nil || n != len(payload) || len(c.writes) != 1 || c.writes[0] != len(payload) {
		t.Fatalf("upstream write capped: n=%d writes=%v", n, c.writes)
	}
	up := make([]byte, 131072)
	s := &Server{pool: newBufferPool(65536, 1)}
	dst := &ss2017DownConn{w: &sent}
	if e := s.copy(&ssDownReadConn{dst}, &ss2017DownConn{r: bytes.NewReader(up)}); e != nil {
		t.Fatal(e)
	}
	if len(dst.writes) != 2 || dst.writes[0] != 65536 || dst.writes[1] != 65536 {
		t.Fatalf("upstream copy writes capped: %v", dst.writes)
	}
}

func TestSS2017DownDeadlinesForwarded(t *testing.T) {
	c := &ss2017DownConn{}
	w := &ssDownReadConn{c}
	at := time.Now().Add(time.Hour)
	if w.SetDeadline(at) != nil || w.SetReadDeadline(at.Add(time.Second)) != nil || w.SetWriteDeadline(at.Add(time.Minute)) != nil {
		t.Fatal("deadline call failed")
	}
	if !c.deadline[0].Equal(at) || !c.deadline[1].Equal(at.Add(time.Second)) || !c.deadline[2].Equal(at.Add(time.Minute)) {
		t.Fatalf("deadlines not forwarded: %v", c.deadline)
	}
	client, server := ss2017TCPPair(t)
	r := &ssDownReadConn{client}
	if e := r.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	_, e := r.Read(make([]byte, 65536))
	if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read deadline not forwarded to TCP: %v", e)
	}
	if e := r.SetReadDeadline(time.Time{}); e != nil {
		t.Fatal(e)
	}
	if _, e := server.Write([]byte("x")); e != nil {
		t.Fatal(e)
	}
	if n, e := r.Read(make([]byte, 16384)); e != nil || n != 1 {
		t.Fatalf("read after clearing deadline n=%d e=%v", n, e)
	}
}

func TestSS2017DownCloseWriteForwarded(t *testing.T) {
	client, server := ss2017TCPPair(t)
	var w net.Conn = &ssDownReadConn{client}
	if _, ok := w.(interface{ CloseWrite() error }); !ok {
		t.Fatal("wrapper hides target CloseWrite")
	}
	if e := closeWrite(w); e != nil {
		t.Fatal(e)
	}
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, e := io.ReadAll(server); e != nil || len(b) != 0 {
		t.Fatalf("target did not observe a real FIN: %v", e)
	}
	if _, e := server.Write([]byte("after-fin")); e != nil {
		t.Fatalf("reverse direction closed by half-close: %v", e)
	}
	server.Close()
	w.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, e := io.ReadAll(w); e != nil || string(b) != "after-fin" {
		t.Fatalf("reverse data after half-close %q %v", b, e)
	}

	peer, stream := ss2017TCPPair(t)
	target, remote := ss2017TCPPair(t)
	response := bytes.Repeat([]byte("relay-half-close-"), 32768)
	got := make(chan []byte, 1)
	go func() {
		remote.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(remote)
		if string(b) == "request" {
			_, _ = remote.Write(response)
		}
		remote.Close()
		got <- b
	}()
	s := &Server{pool: newBufferPool(16384, 4)}
	s.cfg.Limits.DrainTimeout = Duration(5 * time.Second)
	done := make(chan error, 1)
	go func() { done <- s.relayIdle(context.Background(), stream, &ssDownReadConn{target}, 0) }()
	if _, e := peer.Write([]byte("request")); e != nil {
		t.Fatal(e)
	}
	if e := peer.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, e := io.ReadAll(peer)
	if e != nil || !bytes.Equal(b, response) {
		t.Fatalf("response after relayed half-close: got %d/%d bytes err %v", len(b), len(response), e)
	}
	if req := <-got; string(req) != "request" {
		t.Fatalf("target request %q", req)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("relay error %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
}

func TestSS2017DownCancelJoinsBothDirections(t *testing.T) {
	for _, idle := range []time.Duration{0, time.Minute} {
		stream, peer := net.Pipe()
		target, other := net.Pipe()
		s := &Server{pool: newBufferPool(16384, 2)}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.relayIdle(ctx, stream, &ssDownReadConn{target}, idle) }()
		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Fatalf("idle=%v cancel returned %v", idle, e)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("idle=%v cancel did not join both directions", idle)
		}
		peer.Close()
		other.Close()
	}
}

func TestSS2017DownOnlySS2017Wrapped(t *testing.T) {
	out, _ := ss2017TCPPair(t)
	v2017 := startTest(t, Inbound{Protocol: "shadowsocks", SS: &SSOptions{Method: "aes-128-gcm", Password: "down-read-fixture", Salts2017: 16}}, nil)
	v2022 := startTest(t, ssIn(), nil)
	socks := startTest(t, inFor("socks5", nil), nil)
	in2017, in2022, inSocks := v2017.cfg.Inbounds[0], v2022.cfg.Inbounds[0], socks.cfg.Inbounds[0]
	if in2017.ssRuntime == nil || in2017.ssRuntime.v2022 || in2022.ssRuntime == nil || !in2022.ssRuntime.v2022 || inSocks.ssRuntime != nil {
		t.Fatal("unexpected SS runtime classification")
	}
	w, ok := ssDownTarget(in2017, out).(*ssDownReadConn)
	if !ok || w.Conn != net.Conn(out) {
		t.Fatal("SS2017 target not wrapped")
	}
	for _, in := range []Inbound{in2022, inSocks} {
		got := ssDownTarget(in, out)
		if _, raw := got.(*net.TCPConn); !raw || got != net.Conn(out) {
			t.Fatalf("protocol %s ss=%v target was wrapped", in.Protocol, in.ssRuntime != nil)
		}
	}
}
