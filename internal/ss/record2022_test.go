package ss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
)

func Test2022WorkspaceCapacityAndClear(t *testing.T) {
	for _, pool := range []chan []byte{record2022Small, record2022Large} {
		for {
			select {
			case <-pool:
			default:
				goto empty
			}
		}
	empty:
	}
	for _, size := range []int{record2022SmallBytes, record2022LargeBytes} {
		var held [][]byte
		for i := 0; i < 24; i++ {
			p := take2022Workspace(size)
			for j := range p {
				p[j] = 0x7f
			}
			held = append(held, p)
		}
		for _, p := range held {
			release2022Workspace(p)
		}
	}
	if len(record2022Small) != 16 || len(record2022Large) != 4 {
		t.Fatal("cache cap changed")
	}
	for _, size := range []int{record2022SmallBytes, record2022LargeBytes} {
		p := take2022Workspace(size)
		if !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("cross-owner bytes")
		}
		release2022Workspace(p)
	}
}
func Test2022WorkspaceWireAndPrivatePending(t *testing.T) {
	for _, name := range methods[3:] {
		s := server(t, name)
		a, _ := s.aead(seq(7, s.m.keySize))
		for _, size := range []int{0, 1, 1023, 1024, 16384, 16385, 65535} {
			var nonce counter
			payload := bytes.Repeat([]byte{17}, size)
			head, _ := seal(a, &nonce, binary.BigEndian.AppendUint16(nil, uint16(size)))
			body, _ := seal(a, &nonce, payload)
			r := recordReader{r: bytes.NewReader(append(head, body...)), aead: a, max: MaxChunk2022}
			var got bytes.Buffer
			b := make([]byte, 997)
			for {
				n, e := r.Read(b)
				got.Write(b[:n])
				p := take2022Workspace(record2022LargeBytes)
				clear(p)
				release2022Workspace(p)
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(name, size, e)
				}
			}
			if !bytes.Equal(got.Bytes(), payload) || r.pending != nil {
				t.Fatal(name, size, "private pending/bytes")
			}
		}
	}
}

func Test2022WorkspaceConcurrentDifferentKeys(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := methods[3+worker%3]
			m, e := lookup(name)
			if e != nil {
				t.Error(e)
				return
			}
			s, e := NewServer(Config{Method: name, Key: bytes.Repeat([]byte{byte(worker + 11)}, m.keySize), UserID: fmt.Sprint(worker)})
			if e != nil {
				t.Error(e)
				return
			}
			s.now = func() time.Time { return testTime }
			p := bytes.Repeat([]byte{byte(worker + 51)}, 131071)
			salt := seq(worker+41, m.keySize)
			wire := tcpRequest(t, s, salt, uint64(testTime.Unix()), testTarget, 1, p[:4096], p[4096:])
			tr := &memTransport{input: bytes.NewReader(wire)}
			c, e := s.Accept(tr)
			if e != nil {
				t.Error(e)
				return
			}
			var got bytes.Buffer
			b := make([]byte, 997)
			for {
				n, e := c.Read(b)
				got.Write(b[:n])
				runtime.Gosched()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Error(e)
					return
				}
			}
			if !bytes.Equal(got.Bytes(), p) {
				t.Error("read crossed key/workspace owner")
				return
			}
			if _, e = c.Write([]byte("first")); e != nil {
				t.Error(e)
				return
			}
			if _, e = c.Write(p); e != nil {
				t.Error(e)
				return
			}
			plain, _ := responsePlain(t, s, tr.output.Bytes(), salt)
			if !bytes.Equal(plain, append([]byte("first"), p...)) {
				t.Error("write crossed key/workspace owner")
			}
		}()
	}
	wg.Wait()
}
