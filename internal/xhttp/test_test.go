package xhttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const testID = "11111111-1111-4111-8111-111111111111"
const otherID = "22222222-2222-4222-8222-222222222222"

func certificates(t *testing.T) (tls.Certificate, []byte, *x509.CertPool) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	v := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "xh.test"}, DNSNames: []string{"xh.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, v, v, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	c, e := tls.X509KeyPair(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p)
	return c, p, pool
}

type testServer struct {
	s      *Server
	addr   string
	client *http.Client
	tls    *tls.Config
	ca     []byte
	cancel context.CancelFunc
	done   chan error
	proto  string
}

func start(t *testing.T, c Config, proto string, h Handler) *testServer {
	t.Helper()
	if c.Path == "" {
		c.Path = "/xh"
	}
	if c.Host == "" {
		c.Host = "xh.test"
	}
	if c.PairTimeout == 0 {
		c.PairTimeout = 2 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 3 * time.Second
	}
	if c.IOTimeout == 0 {
		c.IOTimeout = time.Second
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = time.Second
	}
	server, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	certificate, p, roots := certificates(t)
	raw, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	alpn := []string{proto}
	listener := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: alpn})
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "xh.test", MinVersion: tls.VersionTLS13, NextProtos: alpn}
	var transport http.RoundTripper
	if proto == "h2" {
		transport = &http2.Transport{TLSClientConfig: clientTLS.Clone()}
	} else {
		transport = &http.Transport{TLSClientConfig: clientTLS.Clone(), ForceAttemptHTTP2: false, MaxConnsPerHost: 8}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ts := &testServer{s: server, addr: raw.Addr().String(), ca: p, tls: clientTLS, client: &http.Client{Transport: transport, Timeout: 5 * time.Second}, cancel: cancel, done: make(chan error, 1), proto: proto}
	go func() { ts.done <- server.Serve(ctx, listener, h) }()
	t.Cleanup(func() {
		cancel()
		switch tr := transport.(type) {
		case *http.Transport:
			tr.CloseIdleConnections()
		case *http2.Transport:
			tr.CloseIdleConnections()
		}
		select {
		case e := <-ts.done:
			if e != nil && !errors.Is(e, context.Canceled) {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return ts
}
func (ts *testServer) request(t *testing.T, method, path string, body io.Reader) *http.Response {
	t.Helper()
	request, e := http.NewRequest(method, "https://"+ts.addr+path, body)
	if e != nil {
		t.Fatal(e)
	}
	request.Host = "xh.test"
	request.Header.Set("Referer", "https://xh.test/?x_padding="+strings.Repeat("X", 100))
	response, e := ts.client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	return response
}
func echo(ctx context.Context, st *Stream, m Metadata) error { _, e := io.Copy(st, st); return e }
func TestPacketUpFixedWireOrderAndDuplicate(t *testing.T) {
	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			ts := start(t, Config{Mode: PacketUp}, proto, echo)
			post := func(seq string, p []byte, intended int) {
				r := ts.request(t, "POST", "/xh/"+testID+"/"+seq, bytes.NewReader(p))
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
				if r.StatusCode != intended {
					t.Fatalf("seq%s status%d", seq, r.StatusCode)
				}
			}
			// Independently fixed wire fact: GET /base/uuid is download; POST .../seq is
			// upload. Sequence 1 may precede0 but must not reorder plaintext.
			post("1", []byte("world"), 200)
			post("1", []byte("DUP"), 409)
			post("0", []byte("hello-"), 200)
			response := ts.request(t, "GET", "/xh/"+testID, nil)
			defer response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal(response.Status)
			}
			p := make([]byte, 11)
			if _, e := io.ReadFull(response.Body, p); e != nil || string(p) != "hello-world" {
				t.Fatal(string(p), e)
			}
			post("0", []byte("OLD"), 409)
			if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") || len(response.Header.Get("X-Padding")) < 100 {
				t.Fatal(response.Header)
			}
			response.Body.Close()
		})
	}
}
func TestStreamingModesDuplexAndEOF(t *testing.T) {
	for _, proto := range []string{"http/1.1", "h2"} {
		for _, mode := range []string{StreamUp, StreamOne} {
			t.Run(proto+mode, func(t *testing.T) {
				ts := start(t, Config{Mode: mode}, proto, func(ctx context.Context, st *Stream, m Metadata) error {
					if _, e := st.Write([]byte("welcome")); e != nil {
						return e
					}
					return echo(ctx, st, m)
				})
				pr, pw := io.Pipe()
				var response *http.Response
				if mode == StreamUp {
					response = ts.request(t, "GET", "/xh/"+testID, nil)
					u := ts.request(t, "POST", "/xh/"+testID, pr)
					defer u.Body.Close()
				} else {
					response = ts.request(t, "POST", "/xh/", pr)
				}
				defer response.Body.Close()
				p := make([]byte, 7)
				if _, e := io.ReadFull(response.Body, p); e != nil || string(p) != "welcome" {
					t.Fatal(string(p), e)
				}
				data := bytes.Repeat([]byte{0x42}, 300000)
				written := make(chan error, 1)
				go func() { _, e := pw.Write(data); pw.Close(); written <- e }()
				p = make([]byte, len(data))
				_, e := io.ReadFull(response.Body, p)
				if e != nil || !bytes.Equal(p, data) {
					t.Fatal("full duplex", e)
				}
				if e := <-written; e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
func TestRejectPathHostPaddingAndMode(t *testing.T) {
	ts := start(t, Config{Mode: PacketUp}, "h2", func(context.Context, *Stream, Metadata) error { t.Error("bad request callback"); return nil })
	for _, v := range []struct {
		path, host, padding string
		status              int
	}{{"/bad/" + testID, "xh.test", strings.Repeat("X", 100), 404}, {"/xh/" + testID, "wrong", strings.Repeat("X", 100), 404}, {"/xh/" + testID, "xh.test", "short", 400}, {"/xh/bad-session", "xh.test", strings.Repeat("X", 100), 400}, {"/xh/" + testID + "/00", "xh.test", strings.Repeat("X", 100), 400}} {
		request, _ := http.NewRequest("GET", "https://"+ts.addr+v.path, nil)
		request.Host = v.host
		request.Header.Set("Referer", "https://xh.test/?x_padding="+v.padding)
		r, e := ts.client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != v.status {
			t.Fatal(v, r.Status)
		}
	}
	r := ts.request(t, "POST", "/xh/", bytes.NewReader([]byte("raw")))
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal(r.Status)
	}
}
func TestUnpairedBudgetsExpiryAndSequenceWindow(t *testing.T) {
	ts := start(t, Config{Mode: PacketUp, MaxSessions: 2, MaxUnpaired: 1, PairTimeout: 50 * time.Millisecond, MaxPacketBytes: 16, MaxBufferedBytes: 16, MaxGlobalBufferedBytes: 16, MaxBufferedPackets: 2}, "h2", echo)
	r := ts.request(t, "POST", "/xh/"+testID+"/1", bytes.NewReader([]byte("first")))
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	r = ts.request(t, "POST", "/xh/"+otherID+"/0", bytes.NewReader([]byte("other")))
	r.Body.Close()
	if r.StatusCode != 429 {
		t.Fatal("unpaired capacity", r.Status)
	}
	r = ts.request(t, "POST", "/xh/"+testID+"/2", bytes.NewReader([]byte("window")))
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("seq window", r.Status)
	}
	time.Sleep(80 * time.Millisecond)
	stats := ts.s.Stats()
	if stats.Sessions != 0 || stats.BufferedBytes != 0 {
		t.Fatal("TTL failed", stats)
	}
	r = ts.request(t, "POST", "/xh/"+testID+"/0", bytes.NewReader([]byte("old")))
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("resurrection", r.Status)
	}
}
func TestTruncatedPacketAndReadBudget(t *testing.T) {
	ts := start(t, Config{Mode: PacketUp, MaxPacketBytes: 16}, "http/1.1", echo)
	c, e := tls.Dial("tcp", ts.addr, ts.tls.Clone())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "POST /xh/%s/0 HTTP/1.1\r\nHost: xh.test\r\nReferer: https://xh.test/?x_padding=%s\r\nContent-Length: 100\r\n\r\n", testID, strings.Repeat("X", 100))
	response, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
	if e != nil || response.StatusCode != 413 {
		t.Fatal(response, e)
	}
}
