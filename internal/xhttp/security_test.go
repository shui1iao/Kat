package xhttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSAndOriginalVLESSAuthenticationRejected(t *testing.T) {
	var auth atomic.Int32
	ts := start(t, Config{Mode: StreamOne}, "h2", originalVLESS(&auth, make(chan string, 1)))
	bad := ts.tls.Clone()
	bad.RootCAs = x509.NewCertPool()
	if c, e := tls.Dial("tcp", ts.addr, bad); e == nil {
		c.Close()
		t.Fatal("unknown CA accepted")
	}
	wrong := append([]byte{0}, make([]byte, 16)...)
	wrong = append(wrong, 0, 1, 1, 187, 1, 127, 0, 0, 1)
	r := ts.request(t, "POST", "/xh/", bytes.NewReader(wrong))
	p, e := io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil && len(p) > 0 {
		t.Fatal(e)
	}
	if len(p) != 0 || auth.Load() != 0 {
		t.Fatal("unauthenticated echo", p, auth.Load())
	}
}
func TestDuplicateDownloadCrossSourceAndTombstones(t *testing.T) {
	ready := make(chan *Stream, 1)
	ts := start(t, Config{Mode: PacketUp}, "h2", func(ctx context.Context, st *Stream, m Metadata) error { ready <- st; <-ctx.Done(); return nil })
	down := ts.request(t, "GET", "/xh/"+testID, nil)
	defer down.Body.Close()
	st := <-ready
	r := ts.request(t, "GET", "/xh/"+testID, nil)
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("duplicate downloader", r.Status)
	}
	if _, e := ts.s.getSession(testID, "192.0.2.10"); !errors.Is(e, ErrAssociation) {
		t.Fatal("source hijack", e)
	}
	st.Close()
	down.Body.Close()
	r = ts.request(t, "POST", "/xh/"+testID+"/0", bytes.NewReader([]byte("late")))
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("retired resurrected", r.Status)
	}
}
func TestRetainedPacketAndInFlightReservationAccounting(t *testing.T) {
	s, e := NewServer(Config{Mode: PacketUp, MaxPacketBytes: 16, MaxBufferedBytes: 32, MaxGlobalBufferedBytes: 32})
	if e != nil {
		t.Fatal(e)
	}
	s.ctx = context.Background()
	ss, e := s.getSession(testID, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	pending, e := ss.reserve(0, 16)
	if e != nil {
		t.Fatal(e)
	}
	ss.close(ErrClosed)
	if s.Stats().BufferedBytes != 16 {
		t.Fatal("inflight allocation lost from budget", s.Stats())
	}
	ss.abortPending(pending)
	if s.Stats().BufferedBytes != 0 {
		t.Fatal(s.Stats())
	}
	ss, e = s.getSession(otherID, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	p, e := ss.reserve(0, 12)
	if e != nil {
		t.Fatal(e)
	}
	if e = ss.commit(0, p, []byte("abcdefghijkl")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 2)
	if _, e = ss.Read(b); e != nil {
		t.Fatal(e)
	}
	if s.Stats().BufferedBytes != 12 {
		t.Fatal("partial read undercharged allocation")
	}
	ss.close(ErrClosed)
	if s.Stats().BufferedBytes != 0 {
		t.Fatal("committed packet not released")
	}
}
func TestPacketEmptyNotInventedEOFAndNoSSE(t *testing.T) {
	ts := start(t, Config{Mode: PacketUp, NoSSEHeader: true}, "h2", echo)
	for seq, p := range [][]byte{nil, []byte("after-empty")} {
		r := ts.request(t, "POST", fmt.Sprintf("/xh/%s/%d", testID, seq), bytes.NewReader(p))
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(r.Status)
		}
	}
	r := ts.request(t, "GET", "/xh/"+testID, nil)
	defer r.Body.Close()
	p := make([]byte, len("after-empty"))
	if _, e := io.ReadFull(r.Body, p); e != nil || string(p) != "after-empty" {
		t.Fatal("zero packet became false EOF", string(p), e)
	}
	if r.Header.Get("Content-Type") == "text/event-stream" {
		t.Fatal("noSSE option ignored")
	}
}
func TestTruncatedPacketAndTotalBudget(t *testing.T) {
	ts := start(t, Config{Mode: PacketUp, IOTimeout: 60 * time.Millisecond, MaxPacketBytes: 16, MaxUploadBytes: 8}, "http/1.1", echo)
	c, e := tls.Dial("tcp", ts.addr, ts.tls.Clone())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(c, "POST /xh/%s/0 HTTP/1.1\r\nHost: xh.test\r\nReferer: https://xh.test/?x_padding=%s\r\nContent-Length: 8\r\n\r\nabc", testID, strings.Repeat("X", 100))
	r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
	if e != nil || r.StatusCode != 400 {
		t.Fatal(r, e)
	}
	r.Body.Close()
	if stats := ts.s.Stats(); stats.BufferedBytes != 0 {
		t.Fatal("truncated reservation leak", stats)
	}
	second := start(t, Config{Mode: PacketUp, MaxUploadBytes: 5}, "h2", echo)
	for seq, expected := range []int{200, 429} {
		r := second.request(t, "POST", fmt.Sprintf("/xh/%s/%d", testID, seq), bytes.NewReader([]byte("abc")))
		r.Body.Close()
		if r.StatusCode != expected {
			t.Fatal("per session upload cap", r.Status, expected)
		}
	}
}
func TestBoundedShutdownBlockedUploadAndConfig(t *testing.T) {
	entered := make(chan struct{})
	ts := start(t, Config{Mode: StreamUp}, "h2", func(ctx context.Context, st *Stream, m Metadata) error {
		close(entered)
		_, e := st.Read(make([]byte, 1))
		return e
	})
	down := ts.request(t, "GET", "/xh/"+testID, nil)
	defer down.Body.Close()
	<-entered
	pr, pw := io.Pipe()
	up := ts.request(t, "POST", "/xh/"+testID, pr)
	defer up.Body.Close()
	ts.cancel()
	pw.Close()
	deadline := time.Now().Add(time.Second)
	for ts.s.Stats().Handlers > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ts.s.Stats().Handlers != 0 {
		t.Fatal("blocked upload did not cancel")
	}
	for _, c := range []Config{{Mode: "unknown"}, {Path: "x"}, {PaddingMin: 2, PaddingMax: 1}, {MaxSessions: -1}, {MaxPacketBytes: 17 * 1024 * 1024}} {
		if _, e := NewServer(c); !errors.Is(e, ErrConfig) {
			t.Fatal(c, e)
		}
	}
}
