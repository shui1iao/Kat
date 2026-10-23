package kernel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func xhIn(cert *TLSConfig) Inbound {
	return Inbound{Protocol: "vless", TLS: cert, Users: []User{{UUID: testUUID}}, Transport: &VTransportOptions{Type: "xhttp", Path: "/xh/", Host: "localhost", MaxStreams: 8, XHTTP: &XHTTPOptions{MaxSessions: 8, MaxRequests: 16, MaxRetired: 32, PairTimeout: Duration(300 * time.Millisecond), IOTimeout: Duration(time.Second), RetiredTTL: Duration(time.Second)}}}
}
func xhClient(t *testing.T, pool *x509.CertPool, h2 bool) *http.Client {
	t.Helper()
	tlsConfig := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	var rt http.RoundTripper
	if h2 {
		rt = &http2.Transport{TLSClientConfig: tlsConfig}
	} else {
		rt = &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: false}
	}
	t.Cleanup(func() {
		if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	})
	return &http.Client{Transport: rt, Timeout: 3 * time.Second}
}
func xhRequest(t *testing.T, client *http.Client, s *Server, method, path string, body io.Reader) *http.Response {
	t.Helper()
	req, e := http.NewRequest(method, "https://"+s.Addresses()[0].String()+path, body)
	if e != nil {
		t.Fatal(e)
	}
	req.Host = "localhost"
	req.Header.Set("Referer", "https://localhost/?x_padding="+strings.Repeat("X", 100))
	req.Header.Set("Content-Type", "application/grpc")
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	return resp
}
func TestXHTTPCoreStreamingEOFPreservesTail(t *testing.T) {
	cert, pool := testCert(t)
	for _, h2 := range []bool{false, true} {
		for _, mode := range []string{"stream-one", "stream-up"} {
			t.Run(fmt.Sprintf("%v/%s", h2, mode), func(t *testing.T) {
				in := xhIn(cert)
				in.Transport.XHTTP.Mode = mode
				s := startTest(t, in, nil)
				target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
					b, e := io.ReadAll(c)
					if e == nil && string(b) == "upload-EOF" {
						writeAll(c, bytes.Repeat([]byte("tail"), 128*1024))
					}
				})
				client := xhClient(t, pool, h2)
				wire := append(peerHeader("vless", 1, target), []byte("upload-EOF")...)
				var download *http.Response
				if mode == "stream-one" {
					download = xhRequest(t, client, s, "POST", "/xh/", bytes.NewReader(wire))
				} else {
					const id = "10000000-0000-4000-8000-000000000001"
					download = xhRequest(t, client, s, "GET", "/xh/"+id, nil)
					upload := xhRequest(t, client, s, "POST", "/xh/"+id, bytes.NewReader(wire))
					io.Copy(io.Discard, upload.Body)
					upload.Body.Close()
				}
				got, e := io.ReadAll(download.Body)
				download.Body.Close()
				want := append([]byte{0, 0}, bytes.Repeat([]byte("tail"), 128*1024)...)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatalf("tail truncated %d/%d %v", len(got), len(want), e)
				}
				waitFor(t, func() bool { return s.logical.Load() == 0 })
			})
		}
	}
}
func TestXHTTPCorePacketEmptyNotEOFAndRetired(t *testing.T) {
	cert, pool := testCert(t)
	s := startTest(t, xhIn(cert), nil)
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		b := make([]byte, 6)
		if _, e := io.ReadFull(c, b); e == nil && string(b) == "abcdef" {
			writeAll(c, []byte("complete"))
		}
	})
	client := xhClient(t, pool, true)
	const id = "10000000-0000-4000-8000-000000000002"
	down := xhRequest(t, client, s, "GET", "/xh/"+id, nil)
	for i, p := range [][]byte{append(peerHeader("vless", 1, target), []byte("abc")...), {}, []byte("def")} {
		up := xhRequest(t, client, s, "POST", fmt.Sprintf("/xh/%s/%d", id, i), bytes.NewReader(p))
		if up.StatusCode != 200 {
			t.Fatal("packet", up.StatusCode)
		}
		io.Copy(io.Discard, up.Body)
		up.Body.Close()
	}
	b, e := io.ReadAll(down.Body)
	down.Body.Close()
	if e != nil || !bytes.Equal(b, append([]byte{0, 0}, []byte("complete")...)) {
		t.Fatalf("empty packet treated as EOF: %x %v", b, e)
	}
	waitFor(t, func() bool { return s.logical.Load() == 0 })
	again := xhRequest(t, client, s, "GET", "/xh/"+id, nil)
	defer again.Body.Close()
	if again.StatusCode != 409 {
		t.Fatal("retired session UUID reused", again.StatusCode)
	}
}
func TestXHTTPAuthAndDifferentUsersIsolated(t *testing.T) {
	cert, pool := testCert(t)
	in := xhIn(cert)
	const second = "11111111-1111-4111-8111-111111111111"
	in.Users = append(in.Users, User{UUID: second})
	s := startTest(t, in, nil)
	var accepted atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { accepted.Add(1); io.Copy(c, c) })
	client := xhClient(t, pool, true)
	bad := peerHeader("vless", 1, target)
	bad[1] ^= 0x40
	resp := xhRequest(t, client, s, "POST", "/xh/", bytes.NewReader(bad))
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if accepted.Load() != 0 {
		t.Fatal("HTTP pairing UUID mistaken for VLESS auth")
	}
	for i, u := range []string{testUUID, second} {
		uuid, _ := parseUUID(u)
		wire := peerHeader("vless", 1, target)
		copy(wire[1:17], uuid[:])
		p := bytes.Repeat([]byte{byte(i + 1)}, 4096)
		wire = append(wire, p...)
		resp := xhRequest(t, client, s, "POST", "/xh/", bytes.NewReader(wire))
		got, e := io.ReadAll(resp.Body)
		resp.Body.Close()
		if e != nil || !bytes.Equal(got, append([]byte{0, 0}, p...)) {
			t.Fatal("user bytes crossed", e)
		}
	}
	if accepted.Load() != 2 {
		t.Fatal("bad authenticated target count")
	}
}
func TestXHTTPLimitsAndStopReclaims(t *testing.T) {
	cert, pool := testCert(t)
	baseline, _ := os.ReadDir("/proc/self/fd")
	in := xhIn(cert)
	in.Transport.MaxStreams = 1
	in.Transport.XHTTP.MaxUnpaired = 1
	in.Transport.XHTTP.PairTimeout = Duration(time.Second)
	s := startTest(t, in, nil)
	client := xhClient(t, pool, true)
	one := xhRequest(t, client, s, "GET", "/xh/10000000-0000-4000-8000-000000000003", nil)
	defer one.Body.Close()
	two := xhRequest(t, client, s, "GET", "/xh/10000000-0000-4000-8000-000000000004", nil)
	io.Copy(io.Discard, two.Body)
	two.Body.Close()
	if two.StatusCode < 400 {
		t.Fatal("unpaired/handler quota bypass")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	if st := s.cfg.Inbounds[0].xhttpServer.Stats(); st.Connections != 0 || st.Sessions != 0 || st.Handlers != 0 || st.BufferedBytes != 0 {
		t.Fatal("XHTTP resources leaked", st)
	}
	if s.logical.Load() != 0 || s.Stats().Active != 0 || s.Stats().Handshakes != 0 {
		t.Fatal("core XHTTP quotas leaked", s.Stats())
	}
	one.Body.Close()
	if rt, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
		rt.CloseIdleConnections()
	}
	waitFor(t, func() bool { fds, _ := os.ReadDir("/proc/self/fd"); return len(fds) <= len(baseline)+1 })
}
func TestXHTTPRejectsInsecureAndUnsupportedCombos(t *testing.T) {
	cert, _ := testCert(t)
	for _, in := range []Inbound{
		{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: testUUID}}, Transport: &VTransportOptions{Type: "xhttp"}},
		{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: testUUID}}, TLS: cert, Transport: &VTransportOptions{Type: "xhttp", XHTTP: &XHTTPOptions{ALPN: []string{"h3"}}}},
		{Protocol: "vless", Listen: "127.0.0.1:0", Users: []User{{UUID: testUUID, Flow: "xtls-rprx-vision"}}, TLS: cert, Transport: &VTransportOptions{Type: "xhttp"}},
	} {
		c := Config{Inbounds: []Inbound{in}}
		if c.Validate() == nil {
			t.Fatal("unsafe XHTTP combo allowed")
		}
	}
}

func TestXHTTPCoreUploadAndBufferBudgets(t *testing.T) {
	cert, pool := testCert(t)
	in := xhIn(cert)
	in.Transport.XHTTP.MaxUploads = 1
	in.Transport.XHTTP.MaxPacketBytes = 128
	in.Transport.XHTTP.MaxBufferedPackets = 2
	in.Transport.XHTTP.MaxBufferedBytes = 256
	in.Transport.XHTTP.MaxGlobalBufferedBytes = 256
	s := startTest(t, in, nil)
	client := xhClient(t, pool, true)
	const id = "10000000-0000-4000-8000-000000000006"
	// No downstream handler yet. A valid known-length upload occupies one packet
	// and its complete allocation until consumed/expired, not just a len estimate.
	first := xhRequest(t, client, s, "POST", "/xh/"+id+"/0", bytes.NewReader(make([]byte, 100)))
	io.Copy(io.Discard, first.Body)
	first.Body.Close()
	if first.StatusCode != 200 {
		t.Fatal(first.StatusCode)
	}
	if st := s.cfg.Inbounds[0].xhttpServer.Stats(); st.BufferedBytes != 100 || st.BufferedPackets != 1 {
		t.Fatal("buffer reservation missing", st)
	}
	second := xhRequest(t, client, s, "POST", "/xh/"+id+"/1", bytes.NewReader(make([]byte, 1)))
	io.Copy(io.Discard, second.Body)
	second.Body.Close()
	if second.StatusCode < 400 {
		t.Fatal("cumulative upload count ignored")
	}
	large := xhRequest(t, client, s, "POST", "/xh/10000000-0000-4000-8000-000000000007/0", bytes.NewReader(make([]byte, 129)))
	io.Copy(io.Discard, large.Body)
	large.Body.Close()
	if large.StatusCode != 413 {
		t.Fatal("max packet bytes ignored", large.StatusCode)
	}
	waitFor(t, func() bool {
		st := s.cfg.Inbounds[0].xhttpServer.Stats()
		return st.BufferedBytes == 0 && st.Sessions == 0
	})
}
func TestXHTTPSlowHandshakeStop(t *testing.T) {
	cert, _ := testCert(t)
	in := xhIn(cert)
	s := startTest(t, in, func(c *Config) { c.Limits.Handshakes = 1 })
	raw, e := net.Dial("tcp", s.Addresses()[0].String())
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	waitFor(t, func() bool { return s.Stats().Handshakes == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	if s.Stats().Handshakes != 0 || s.Stats().Active != 0 {
		t.Fatal("TLS handshake quota leaked on stop", s.Stats())
	}
}
