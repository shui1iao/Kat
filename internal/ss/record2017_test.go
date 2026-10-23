package ss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestRecordWorkspaceBoundAndClear(t *testing.T) {
	for {
		select {
		case <-recordWorkspaces:
		default:
			goto drained
		}
	}
drained:
	var held []*[recordWorkspaceBytes]byte
	for i := 0; i < recordWorkspaceSlots+8; i++ {
		p := takeRecordWorkspace()
		for j := range p {
			p[j] = 0x77
		}
		held = append(held, p)
	}
	for _, p := range held {
		releaseRecordWorkspace(p)
	}
	if len(recordWorkspaces) != recordWorkspaceSlots {
		t.Fatal("unbounded/incorrect cache")
	}
	for i := 0; i < recordWorkspaceSlots; i++ {
		p := takeRecordWorkspace()
		if !bytes.Equal(p[:], make([]byte, recordWorkspaceBytes)) {
			t.Fatal("plaintext/ciphertext retained across owners")
		}
	}
}
func TestRecord2017PendingHasPrivateOwnership(t *testing.T) {
	for _, name := range methods[:3] {
		s := server(t, name)
		a, e := s.aead(seq(3, s.m.keySize))
		if e != nil {
			t.Fatal(e)
		}
		payload := bytes.Repeat([]byte{0x42}, MaxChunk2017)
		var nonce counter
		h, _ := seal(a, &nonce, []byte{0x3f, 0xff})
		b, _ := seal(a, &nonce, payload)
		r := recordReader{r: bytes.NewReader(append(h, b...)), aead: a, max: MaxChunk2017}
		first := make([]byte, 7)
		if n, e := r.Read(first); e != nil || n != 7 {
			t.Fatal(n, e)
		}
		workspace := takeRecordWorkspace()
		clear(workspace[:])
		releaseRecordWorkspace(workspace)
		rest, e := io.ReadAll(&r)
		if e != nil || !bytes.Equal(append(first, rest...), payload) {
			t.Fatal("pending aliased pool", e)
		}
		if r.pending != nil {
			t.Fatal("consumed plaintext retained")
		}
	}
}
func TestRecord2017WorkspaceNonceAndTag(t *testing.T) {
	s := server(t, AES128GCM)
	a, _ := s.aead(seq(4, 16))
	n := counter{exhausted: true}
	if _, e := sealAppend(a, &n, nil, []byte("x")); e != ErrNonceExhausted {
		t.Fatal(e)
	}
	if _, e := openInPlace(a, &n, make([]byte, 16)); e != ErrNonceExhausted {
		t.Fatal(e)
	}
	n = counter{}
	for i := range n.value {
		n.value[i] = math.MaxUint8
	}
	if _, e := sealAppend(a, &n, make([]byte, 0, 64), []byte("x")); e != nil || !n.exhausted {
		t.Fatal("nonce did not exhaust", e)
	}
	n = counter{}
	if _, e := openInPlace(a, &n, make([]byte, 32)); e != ErrAuth || n.value != [12]byte{} {
		t.Fatal("bad tag advanced nonce", e)
	}
}

// Test-only interleaving: all three 2017 ciphers with separate keys share the
// bounded workspace cache, never plaintext ownership or nonce state.
func TestRecord2017ConcurrentDifferentKeys(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := methods[worker%3]
			m, e := lookup(name)
			if e != nil {
				t.Error(e)
				return
			}
			s, e := NewServer(Config{Method: name, Key: bytes.Repeat([]byte{byte(worker + 1)}, m.keySize), UserID: fmt.Sprint(worker)})
			if e != nil {
				t.Error(e)
				return
			}
			s.now = func() time.Time { return testTime }
			payload := bytes.Repeat([]byte{byte(31 + worker)}, 131071)
			salt := seq(worker+17, m.keySize)
			wire := tcpRequest(t, s, salt, uint64(testTime.Unix()), testTarget, 1, payload[:4096], payload[4096:])
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
			if !bytes.Equal(got.Bytes(), payload) {
				t.Errorf("reader owner %d corrupted", worker)
				return
			}
			if _, e = c.Write([]byte("first")); e != nil {
				t.Error(e)
				return
			}
			if _, e = c.Write(payload); e != nil {
				t.Error(e)
				return
			}
			out := tr.output.Bytes()
			a, e := s.aead(out[:m.keySize])
			if e != nil {
				t.Error(e)
				return
			}
			out = out[m.keySize:]
			var nonce counter
			var plain []byte
			for len(out) > 0 {
				if len(out) < 18 {
					t.Error("short length record")
					return
				}
				length, e := open(a, &nonce, out[:18])
				if e != nil {
					t.Error(e)
					return
				}
				out = out[18:]
				size := int(binary.BigEndian.Uint16(length))
				if len(out) < size+16 {
					t.Error("short data record")
					return
				}
				data, e := open(a, &nonce, out[:size+16])
				if e != nil {
					t.Error(e)
					return
				}
				plain = append(plain, data...)
				out = out[size+16:]
			}
			if !bytes.Equal(plain, append([]byte("first"), payload...)) {
				t.Errorf("writer owner %d corrupted", worker)
			}
		}()
	}
	wg.Wait()
}
