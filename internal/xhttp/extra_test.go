package xhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestIndependentFixedFactsAndQueryFallback(t *testing.T) {
	raw, e := os.ReadFile("testdata/wire-facts.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]string
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	ts := start(t, Config{Mode: PacketUp}, "h2", echo)
	for _, pair := range []struct{ path, data string }{{"upload_1_path", "packet_1_hex"}, {"upload_0_path", "packet_0_hex"}} {
		p, e := hex.DecodeString(f[pair.data])
		if e != nil {
			t.Fatal(e)
		}
		request, _ := http.NewRequest("POST", "https://"+ts.addr+f[pair.path]+f["query_fallback"], bytes.NewReader(p))
		request.Host = "xh.test"
		r, e := ts.client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(r.Status)
		}
	}
	request, _ := http.NewRequest("GET", "https://"+ts.addr+f["download_path"], nil)
	request.Host = "xh.test"
	request.Header.Set("Referer", f["referer"])
	r, e := ts.client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	expected, _ := hex.DecodeString(f["plaintext_hex"])
	p := make([]byte, len(expected))
	if _, e = io.ReadFull(r.Body, p); e != nil || !bytes.Equal(p, expected) {
		t.Fatal("fixture plaintext", string(p), e)
	}
}
func TestConcurrentDuplicateAndCrossSessionIsolation(t *testing.T) {
	s, e := NewServer(Config{Mode: PacketUp})
	if e != nil {
		t.Fatal(e)
	}
	s.ctx = context.Background()
	a, _ := s.getSession(testID, "127.0.0.1")
	b, _ := s.getSession(otherID, "127.0.0.1")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := a.reserve(0, 4)
			if e == nil {
				e = a.commit(0, p, []byte("AAAA"))
			}
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, ErrAssociation) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal("duplicate admitted", success)
	}
	p, e := b.reserve(0, 4)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.commit(0, p, []byte("BBBB")); e != nil {
		t.Fatal(e)
	}
	one, two := make([]byte, 4), make([]byte, 4)
	a.Read(one)
	b.Read(two)
	if string(one) != "AAAA" || string(two) != "BBBB" {
		t.Fatal("cross-session bytes", one, two)
	}
	a.close(ErrClosed)
	b.close(ErrClosed)
	if st := s.Stats(); st.Sessions != 0 || st.BufferedBytes != 0 {
		t.Fatal(st)
	}
}
func TestUnknownLengthPacketAndReadDeadline(t *testing.T) {
	ts := start(t, Config{Mode: PacketUp, MaxPacketBytes: 16}, "h2", echo)
	r := ts.request(t, "POST", "/xh/"+testID+"/0", io.NopCloser(bytes.NewReader([]byte("unknown"))))
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	r = ts.request(t, "GET", "/xh/"+testID, nil)
	defer r.Body.Close()
	p := make([]byte, 7)
	if _, e := io.ReadFull(r.Body, p); e != nil || string(p) != "unknown" {
		t.Fatal(p, e)
	}
	result := make(chan error, 1)
	other := start(t, Config{Mode: PacketUp}, "h2", func(ctx context.Context, st *Stream, m Metadata) error {
		if e := st.CloseWrite(); !errors.Is(e, ErrHalfCloseUnsupported) {
			result <- e
			return e
		}
		st.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
		_, e := st.Read(make([]byte, 1))
		result <- e
		return e
	})
	down := other.request(t, "GET", "/xh/"+otherID, nil)
	defer down.Body.Close()
	if e := <-result; !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("deadline not enforced", e)
	}
}
