package ss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// residentWire seals the given record sizes as one SS2022 record stream.
func residentWire(t *testing.T, s *Server, sizes []int) ([]byte, []byte) {
	t.Helper()
	a, e := s.aead(seq(0x31, s.m.keySize))
	if e != nil {
		t.Fatal(e)
	}
	var n counter
	var wire, plain []byte
	for i, size := range sizes {
		p := make([]byte, size)
		for j := range p {
			p[j] = byte(i*131 + j*7 + 1)
		}
		l, _ := seal(a, &n, binary.BigEndian.AppendUint16(nil, uint16(size)))
		b, _ := seal(a, &n, p)
		wire = append(append(wire, l...), b...)
		plain = append(plain, p...)
	}
	return wire, plain
}
func residentReader(t *testing.T, s *Server, wire []byte) *recordReader {
	t.Helper()
	a, _ := s.aead(seq(0x31, s.m.keySize))
	return &recordReader{r: bytes.NewReader(wire), aead: a, max: MaxChunk2022}
}

// readAllWith reads to EOF with a fixed caller size; every returned chunk is
// copied into its own slice so later reads cannot alias earlier results.
func readAllWith(t *testing.T, r io.Reader, caller int) ([][]byte, error) {
	t.Helper()
	var out [][]byte
	b := make([]byte, caller)
	for {
		n, e := r.Read(b)
		if n > 0 {
			out = append(out, append([]byte(nil), b[:n]...))
		}
		if e != nil {
			return out, e
		}
	}
}

func TestSS2022ResidentRecordLargerThanCaller(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		for _, c := range []struct{ record, caller int }{{32734, 16384}, {65535, 1024}, {16385, 16384}} {
			wire, plain := residentWire(t, s, []int{c.record, c.record, c.record})
			r := residentReader(t, s, wire)
			chunks, e := readAllWith(t, r, c.caller)
			if e != io.EOF || !bytes.Equal(bytes.Join(chunks, nil), plain) {
				t.Fatal(name, c, e, "bytes differ")
			}
			for _, ch := range chunks {
				if len(ch) > c.caller {
					t.Fatal(name, c, "chunk larger than caller")
				}
			}
			if r.pending != nil {
				t.Fatal(name, c, "pending used for a large short-caller record")
			}
			if r.resident != nil || r.off != 0 || r.end != 0 {
				t.Fatal(name, c, "resident not released at EOF")
			}
		}
	}
}

func TestSS2022ResidentRecordNotLargerThanCaller(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		wire, plain := residentWire(t, s, []int{1, 1023, 1024, 16384, 32734})
		r := residentReader(t, s, wire)
		b := make([]byte, 32734)
		var got []byte
		for {
			n, e := r.Read(b)
			got = append(got, b[:n]...)
			if r.resident != nil {
				t.Fatal(name, "resident allocated although every record fits the caller")
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(name, e)
			}
		}
		if !bytes.Equal(got, plain) {
			t.Fatal(name, "bytes differ")
		}
	}
}

func TestSS2022ResidentShortReads7(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		wire, plain := residentWire(t, s, []int{32734, 7, 1024, 65535, 0, 16385})
		chunks, e := readAllWith(t, residentReader(t, s, wire), 7)
		if e != io.EOF || !bytes.Equal(bytes.Join(chunks, nil), plain) {
			t.Fatal(name, e, "7-byte reads differ")
		}
	}
}

func TestSS2022ResidentDataThenError(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		wire, plain := residentWire(t, s, []int{32734, 32734})
		// Truncate inside the second record: the whole first record must be
		// delivered before the sticky error, never mixed into one call.
		cut := len(wire) - 100
		r := residentReader(t, s, wire[:cut])
		chunks, e := readAllWith(t, r, 16384)
		if !errors.Is(e, io.ErrUnexpectedEOF) {
			t.Fatal(name, "wanted ErrUnexpectedEOF, got", e)
		}
		if !bytes.Equal(bytes.Join(chunks, nil), plain[:32734]) {
			t.Fatal(name, "data before error differs")
		}
		if r.resident != nil {
			t.Fatal(name, "resident kept after error")
		}
		if n, e2 := r.Read(make([]byte, 16384)); n != 0 || e2 != e {
			t.Fatal(name, "error not sticky", n, e2)
		}
	}
}

func TestSS2022ResidentReturnedDataNotOverwritten(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		wire, plain := residentWire(t, s, []int{32734, 32734, 65535})
		r := residentReader(t, s, wire)
		// The caller keeps every returned slice of ONE reused buffer region:
		// later reads into fresh caller buffers must not modify them.
		var kept [][]byte
		for {
			b := make([]byte, 16384)
			n, e := r.Read(b)
			if n > 0 {
				kept = append(kept, b[:n])
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(name, e)
			}
		}
		if !bytes.Equal(bytes.Join(kept, nil), plain) {
			t.Fatal(name, "previously returned caller data changed")
		}
	}
}

func TestSS2022ResidentCloseClearsAndReleases(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		tail := bytes.Repeat([]byte{0x5a}, 32734)
		wire := tcpRequest(t, s, seq(0x41, s.m.keySize), uint64(testTime.Unix()), testTarget, 1, []byte("hi"), tail)
		tr := &memTransport{input: bytes.NewReader(wire)}
		c, e := s.Accept(tr)
		if e != nil {
			t.Fatal(e)
		}
		if c.reader.resident != nil {
			t.Fatal(name, "resident allocated by Accept")
		}
		b := make([]byte, 16384)
		if n, e := c.Read(b); n != 2 || e != nil {
			t.Fatal(name, "initial payload", n, e)
		}
		if n, e := c.Read(b); n != 16384 || e != nil {
			t.Fatal(name, n, e)
		}
		backing := c.reader.resident[:cap(c.reader.resident)]
		if c.reader.end-c.reader.off != 32734-16384 {
			t.Fatal(name, "unexpected window")
		}
		if e := c.Close(); e != nil || !tr.closed {
			t.Fatal(name, "close", e)
		}
		if c.reader.resident != nil || c.reader.off != 0 || c.reader.end != 0 {
			t.Fatal(name, "resident not released on Close")
		}
		if !bytes.Equal(backing, make([]byte, len(backing))) {
			t.Fatal(name, "resident not cleared on Close")
		}
	}
}

func TestSS2022ResidentLazyAndCapacityBound(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		wire, plain := residentWire(t, s, []int{100, 900, 1023, 2000, 65535, 1024, 40000, 16385, 65535, 3})
		r := residentReader(t, s, wire)
		b := make([]byte, 1024)
		var got []byte
		var first []byte
		for {
			n, e := r.Read(b)
			got = append(got, b[:n]...)
			if r.resident != nil {
				if cap(r.resident) != MaxChunk2022+r.aead.Overhead() || cap(r.resident) != residentBytes {
					t.Fatal(name, "resident capacity", cap(r.resident))
				}
				if first == nil {
					first = r.resident[:1]
				} else if &first[0] != &r.resident[:1][0] {
					t.Fatal(name, "resident reallocated instead of reused")
				}
			} else if len(got) > 100+900+1023 && e == nil && len(got) < len(plain) {
				t.Fatal(name, "resident missing for a record larger than the caller")
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(name, e)
			}
		}
		if !bytes.Equal(got, plain) {
			t.Fatal(name, "bytes differ")
		}
		// Small records only, small caller: never allocates the resident buffer.
		wire, _ = residentWire(t, s, []int{900, 1023, 7})
		r = residentReader(t, s, wire)
		if _, e := readAllWith(t, r, 5); e != io.EOF || r.resident != nil {
			t.Fatal(name, "resident allocated for records < 1024", e)
		}
	}
}

func TestSS2022ResidentTamperAndReplayRejected(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		wire, plain := residentWire(t, s, []int{32734, 32734})
		bad := bytes.Clone(wire)
		bad[18+32734+16-1] ^= 1 // last tag byte of the first payload
		r := residentReader(t, s, bad)
		chunks, e := readAllWith(t, r, 16384)
		if !errors.Is(e, ErrAuth) || len(chunks) != 0 || r.resident != nil {
			t.Fatal(name, "tampered tag", e, len(chunks))
		}
		bad = bytes.Clone(wire)
		bad[18+32734+16+18+5] ^= 1 // inside the second payload
		r = residentReader(t, s, bad)
		chunks, e = readAllWith(t, r, 16384)
		if !errors.Is(e, ErrAuth) || !bytes.Equal(bytes.Join(chunks, nil), plain[:32734]) || r.resident != nil {
			t.Fatal(name, "tampered second record", e)
		}
		// Replaying an accepted connection's salt is still refused at Accept.
		tail := bytes.Repeat([]byte{9}, 32734)
		req := tcpRequest(t, s, seq(0x51, s.m.keySize), uint64(testTime.Unix()), testTarget, 1, []byte("x"), tail)
		c, e := s.Accept(&memTransport{input: bytes.NewReader(req)})
		if e != nil {
			t.Fatal(name, e)
		}
		if out, e := readAllWith(t, c, 16384); e != io.EOF || !bytes.Equal(bytes.Join(out, nil), append([]byte("x"), tail...)) {
			t.Fatal(name, "first accept data", e)
		}
		if _, e = s.Accept(&memTransport{input: bytes.NewReader(req)}); e == nil {
			t.Fatal(name, "replayed salt accepted")
		}
	}
}

func TestSS2022ResidentDeadlineCancelAndHalfClose(t *testing.T) {
	// Two tail records: a complete 65535B record, then a 32734B record that the
	// peer truncates. tcpRequest splits the tail at MaxChunk2022, so the record
	// layout is asserted before it is relied upon.
	tail := make([]byte, MaxChunk2022+32734)
	for i := range tail {
		tail[i] = byte(i*7 + 3)
	}
	first := 1 + MaxChunk2022
	salt := seq(0x61, 16)
	{
		sc := server(t, AES128GCM2022)
		wire := tcpRequest(t, sc, salt, uint64(testTime.Unix()), testTarget, 1, []byte("y"), tail)
		c, e := sc.Accept(&memTransport{input: bytes.NewReader(wire)})
		if e != nil {
			t.Fatal(e)
		}
		var sizes []int
		buf := make([]byte, MaxChunk2022)
		for {
			n, e := c.Read(buf)
			if n > 0 {
				sizes = append(sizes, n)
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		if len(sizes) != 3 || sizes[0] != 1 || sizes[1] != MaxChunk2022 || sizes[2] != 32734 {
			t.Fatalf("tail record layout %v, want initial 1 then 2 records [65535 32734]", sizes)
		}
	}
	for _, mode := range []string{"deadline", "cancel"} {
		s := server(t, AES128GCM2022)
		wire := tcpRequest(t, s, salt, uint64(testTime.Unix()), testTarget, 1, []byte("y"), tail)
		cut := len(wire) - 1000 // inside the second (32734B) tail record
		a, b := net.Pipe()
		go func() { b.Write(wire[:cut]) }()
		// Backstop deadline: every blocking read returns with an error instead of
		// hanging, and failures are judged only on the test goroutine.
		a.SetReadDeadline(time.Now().Add(3 * time.Second))
		c, e := s.Accept(a)
		if e != nil {
			b.Close()
			t.Fatal(mode, e)
		}
		buf := make([]byte, 16384)
		var got []byte
		for len(got) < first {
			n, e := c.Read(buf)
			if e != nil {
				b.Close()
				t.Fatalf("%s: first record not delivered (%d of %d bytes): %v", mode, len(got), first, e)
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got[1:], tail[:MaxChunk2022]) {
			b.Close()
			t.Fatal(mode, "first record bytes differ")
		}
		if mode == "deadline" {
			a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, e = c.Read(buf)
			if !errors.Is(e, os.ErrDeadlineExceeded) {
				b.Close()
				t.Fatal("deadline", e)
			}
			if c.reader.resident != nil {
				b.Close()
				t.Fatal("resident kept after deadline error")
			}
			c.Close()
		} else {
			a.SetReadDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() {
				_, e := c.Read(buf)
				done <- e
			}()
			time.Sleep(30 * time.Millisecond)
			if e := c.Close(); e != nil {
				b.Close()
				t.Fatal("close", e)
			}
			select {
			case e := <-done:
				if e == nil || errors.Is(e, os.ErrDeadlineExceeded) {
					b.Close()
					t.Fatal("blocked read was not ended by Close", e)
				}
			case <-time.After(2 * time.Second):
				b.Close()
				t.Fatal("blocked read survived Close")
			}
			if c.reader.resident != nil {
				b.Close()
				t.Fatal("resident kept after cancel")
			}
		}
		b.Close()
	}
	// CloseWrite does not disturb the read side or its resident window.
	s := server(t, AES128GCM2022)
	wire := tcpRequest(t, s, salt, uint64(testTime.Unix()), testTarget, 1, []byte("y"), tail)
	tr := &halfTransport{memTransport: memTransport{input: bytes.NewReader(wire)}}
	c, e := s.Accept(tr)
	if e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 16384)
	n1, _ := c.Read(buf)
	n2, _ := c.Read(buf)
	if e = c.CloseWrite(); e != nil || !tr.half || tr.closed {
		t.Fatal("closewrite", e)
	}
	rest, e := readAllWith(t, c, 16384)
	if e != io.EOF || n1+n2+len(bytes.Join(rest, nil)) != 1+len(tail) {
		t.Fatal("read after CloseWrite", e)
	}
}
func s2(t *testing.T, a net.Conn) (*TCPConn, error) {
	t.Helper()
	s := server(t, AES128GCM2022)
	return s.Accept(a)
}

func TestSS2022ResidentSS2017Unaffected(t *testing.T) {
	for _, name := range methods[:3] {
		s := server(t, name)
		tail := bytes.Repeat([]byte{0x77}, 3*MaxChunk2017+5)
		wire := tcpRequest(t, s, seq(0x71, s.m.keySize), uint64(testTime.Unix()), testTarget, 0, []byte("z"), tail)
		c, e := s.Accept(&memTransport{input: bytes.NewReader(wire)})
		if e != nil {
			t.Fatal(name, e)
		}
		chunks, e := readAllWith(t, c, 7)
		if e != io.EOF || !bytes.Equal(bytes.Join(chunks, nil), append([]byte("z"), tail...)) {
			t.Fatal(name, e)
		}
		if c.reader.resident != nil || c.reader.off != 0 || c.reader.end != 0 {
			t.Fatal(name, "2017 used the 2022 resident buffer")
		}
	}
}

func TestSS2022ResidentConcurrentReadAndClose(t *testing.T) {
	for i := 0; i < 40; i++ {
		s := server(t, AES128GCM2022)
		tail := bytes.Repeat([]byte{byte(i)}, 32734*3)
		wire := tcpRequest(t, s, seq(0x80+i, s.m.keySize), uint64(testTime.Unix()), testTarget, 1, []byte("c"), tail)
		a, b := net.Pipe()
		go func() {
			b.Write(wire)
			b.Close()
		}()
		c, e := s.Accept(a)
		if e != nil {
			t.Fatal(e)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, 16384)
			for {
				if _, e := c.Read(buf); e != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%5) * time.Millisecond)
			c.Close()
		}()
		wg.Wait()
		c.Close()
		if c.reader.resident != nil {
			t.Fatal("resident survived concurrent Close")
		}
	}
}
