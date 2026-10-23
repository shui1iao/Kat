package ss

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type copy2022Writer struct {
	bytes.Buffer
	sizes   []int
	short   bool
	err     error
	observe func()
}

func (w *copy2022Writer) Write(p []byte) (int, error) {
	if w.observe != nil {
		w.observe()
	}
	w.sizes = append(w.sizes, len(p))
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return len(p) - 1, nil
	}
	return w.Buffer.Write(p)
}
func TestCopy2022WholeRecordsAllCiphers(t *testing.T) {
	for _, name := range methods[3:] {
		srv := server(t, name)
		sizes := []int{0, 1, 1023, 1024, 16384, 16385, 65535}
		wire, plain := residentWire(t, srv, sizes)
		for _, readSize := range []int{1024, 16384, 65536} {
			c := &TCPConn{server: srv, reader: *residentReader(t, srv, wire)}
			w := new(copy2022Writer)
			w.observe = func() {
				// The old receive path never allocated a resident buffer for these
				// records when the configured relay buffer could hold all of them.
				if readSize == 65536 && c.reader.resident != nil {
					t.Error("new idle memory")
				}
			}
			n, err := c.Write2022To(w, readSize)
			if err != nil || n != int64(len(plain)) || !bytes.Equal(w.Bytes(), plain) {
				t.Fatal(name, readSize, n, err)
			}
			want := sizes[1:]
			if len(w.sizes) != len(want) {
				t.Fatal(name, "records fragmented", w.sizes)
			}
			for i, n := range want {
				if w.sizes[i] != n {
					t.Fatal(name, w.sizes)
				}
			}
			if c.reader.resident != nil || c.reader.pending != nil {
				t.Fatal("not released on EOF")
			}
		}
	}
}
func TestCopy2022PendingAndPartialResident(t *testing.T) {
	srv := server(t, methods[3])
	wire, plain := residentWire(t, srv, []int{32734, 32734})
	c := &TCPConn{server: srv, reader: *residentReader(t, srv, wire)}
	c.reader.pending = []byte("initial")
	prefix := make([]byte, 17)
	if n, err := c.Read(prefix); n != 7 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := c.Read(prefix); n != 17 || err != nil {
		t.Fatal(n, err)
	}
	var w bytes.Buffer
	n, err := c.Write2022To(&w, 16384)
	if err != nil || n != int64(len(plain)-17) || !bytes.Equal(w.Bytes(), plain[17:]) {
		t.Fatal(n, err)
	}
}
func TestCopy2022ErrorsStickyAndCleared(t *testing.T) {
	for _, name := range methods[3:] {
		srv := server(t, name)
		wire, plain := residentWire(t, srv, []int{32734, 32734})
		for _, badAuth := range []bool{false, true} {
			input := append([]byte(nil), wire...)
			if badAuth {
				input[len(input)-1] ^= 1
			} else {
				input = input[:len(input)-100]
			}
			c := &TCPConn{server: srv, reader: *residentReader(t, srv, input)}
			var out bytes.Buffer
			n, err := c.Write2022To(&out, 16384)
			want := io.ErrUnexpectedEOF
			if badAuth {
				want = ErrAuth
			}
			if !errors.Is(err, want) || n != 32734 || !bytes.Equal(out.Bytes(), plain[:32734]) {
				t.Fatal(name, n, err)
			}
			if c.reader.resident != nil {
				t.Fatal("resident retained on read error")
			}
			if n, e := c.Read(make([]byte, 32)); n != 0 || e != err {
				t.Fatal("not sticky", n, e)
			}
		}
		for _, w := range []*copy2022Writer{{short: true}, {err: io.ErrClosedPipe}} {
			c := &TCPConn{server: srv, reader: *residentReader(t, srv, wire)}
			_, err := c.Write2022To(w, 16384)
			want := io.ErrClosedPipe
			if w.short {
				want = io.ErrShortWrite
			}
			if err != want {
				t.Fatal(name, err)
			}
			if c.reader.resident != nil && !bytes.Equal(c.reader.resident, make([]byte, len(c.reader.resident))) {
				t.Fatal("plaintext retained after write failure")
			}
		}
	}
}
