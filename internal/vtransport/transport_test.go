package vtransport

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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"
)

type harness struct {
	s         *Server
	addr      string
	clientTLS *tls.Config
	certPEM   []byte
	cancel    context.CancelFunc
	done      chan error
}

func cert(t *testing.T) (tls.Certificate, []byte, *x509.CertPool) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "vt.test"}, DNSNames: []string{"vt.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	c, e := tls.X509KeyPair(cp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cp)
	return c, cp, pool
}
func start(t *testing.T, c Config, h Handler) *harness {
	t.Helper()
	certificate, public, pool := cert(t)
	if c.Path == "" {
		c.Path = "/tunnel"
	}
	if c.Host == "" {
		c.Host = "vt.test"
	}
	if c.Kind == GRPC && c.ServiceName == "" {
		c.ServiceName = "vt"
	}
	if c.IOTimeout == 0 {
		c.IOTimeout = 2 * time.Second
	}
	if c.HeaderTimeout == 0 {
		c.HeaderTimeout = time.Second
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = time.Second
	}
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	alpn := []string{"http/1.1"}
	if c.Kind == GRPC {
		alpn = []string{"h2"}
	}
	l := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: alpn})
	ctx, cancel := context.WithCancel(context.Background())
	out := &harness{s: s, addr: listener.Addr().String(), certPEM: public, clientTLS: &tls.Config{RootCAs: pool, ServerName: "vt.test", MinVersion: tls.VersionTLS13, NextProtos: alpn}, cancel: cancel, done: make(chan error, 1)}
	go func() { out.done <- s.Serve(ctx, l, h) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-out.done:
			if e != nil && !errors.Is(e, context.Canceled) {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("Serve shutdown did not complete")
		}
	})
	return out
}
func (h *harness) dial(t *testing.T) *tls.Conn {
	t.Helper()
	c, e := tls.Dial("tcp", h.addr, h.clientTLS.Clone())
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}
func echo(ctx context.Context, st *Stream, m Metadata) error { _, e := io.Copy(st, st); return e }
func TestUpgradePreReadBytesAndServerFirst(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			h := start(t, Config{Kind: HTTPUpgrade}, func(ctx context.Context, st *Stream, m Metadata) error {
				if first {
					if _, e := st.Write([]byte("welcome")); e != nil {
						return e
					}
				}
				return echo(ctx, st, m)
			})
			c := h.dial(t)
			defer c.Close()
			request := "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"
			payload := bytes.Repeat([]byte("abc"), 50000)
			if !first {
				if e := writeAll(c, append([]byte(request), payload...)); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := writeAll(c, []byte(request)); e != nil {
					t.Fatal(e)
				}
			}
			r := bufio.NewReader(c)
			response, e := http.ReadResponse(r, &http.Request{Method: "GET"})
			if e != nil || response.StatusCode != 101 {
				t.Fatal(response, e)
			}
			if first {
				b := make([]byte, 7)
				if _, e = io.ReadFull(r, b); e != nil || string(b) != "welcome" {
					t.Fatal(string(b), e)
				}
				if e = writeAll(c, payload); e != nil {
					t.Fatal(e)
				}
			}
			got := make([]byte, len(payload))
			if _, e = io.ReadFull(r, got); e != nil || !bytes.Equal(payload, got) {
				t.Fatal("pre-read/data corruption", e)
			}
		})
	}
}
func TestWebSocketEarlyDataAndLargeStream(t *testing.T) {
	for _, early := range []bool{false, true} {
		t.Run(fmt.Sprint(early), func(t *testing.T) {
			metadata := make(chan Metadata, 1)
			h := start(t, Config{Kind: WebSocket, MaxEarlyData: 1024}, func(ctx context.Context, st *Stream, m Metadata) error { metadata <- m; return echo(ctx, st, m) })
			httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: h.clientTLS.Clone()}}
			headers := http.Header{"Host": []string{"vt.test"}}
			options := &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: headers, Host: "vt.test"}
			initial := []byte("initial-VLESS-bytes")
			if early {
				options.Subprotocols = []string{base64.RawURLEncoding.EncodeToString(initial)}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ws, _, e := websocket.Dial(ctx, "wss://"+h.addr+"/tunnel", options)
			if e != nil {
				t.Fatal(e)
			}
			defer ws.CloseNow()
			nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
			if early {
				p := make([]byte, len(initial))
				if _, e = io.ReadFull(nc, p); e != nil || !bytes.Equal(p, initial) {
					t.Fatal("early bytes", e)
				}
			}
			payload := bytes.Repeat([]byte("ws-data"), 30000)
			if _, e = nc.Write(payload); e != nil {
				t.Fatal(e)
			}
			p := make([]byte, len(payload))
			if _, e = io.ReadFull(nc, p); e != nil || !bytes.Equal(p, payload) {
				t.Fatal("WS stream", e)
			}
			m := <-metadata
			if m.EarlyDataBytes != map[bool]int{true: len(initial), false: 0}[early] {
				t.Fatal(m)
			}
		})
	}
}
func grpcMessage(data ...[]byte) []byte {
	var body []byte
	for _, p := range data {
		body = append(body, 10)
		body = binary.AppendUvarint(body, uint64(len(p)))
		body = append(body, p...)
	}
	out := []byte{0}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	return append(out, body...)
}
func TestGRPCTunAndTunMultiFullDuplex(t *testing.T) {
	for _, mode := range []string{"Tun", "TunMulti"} {
		t.Run(mode, func(t *testing.T) {
			h := start(t, Config{Kind: GRPC}, func(ctx context.Context, st *Stream, m Metadata) error {
				if _, e := st.Write([]byte("welcome")); e != nil {
					return e
				}
				return echo(ctx, st, m)
			})
			pr, pw := io.Pipe()
			request, e := http.NewRequest("POST", "https://"+h.addr+"/vt/"+mode, pr)
			if e != nil {
				t.Fatal(e)
			}
			request.Host = "vt.test"
			request.Header.Set("Content-Type", "application/grpc")
			request.Header.Set("Te", "trailers")
			tr := &http2.Transport{TLSClientConfig: h.clientTLS.Clone()}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal(response.Status)
			}
			decoded := &grpcReader{r: response.Body, max: 1048576, fields: 256, multi: mode == "TunMulti"}
			greet := make([]byte, 7)
			if _, e = io.ReadFull(decoded, greet); e != nil || string(greet) != "welcome" {
				t.Fatal("gRPC server-first", e)
			}
			payload := bytes.Repeat([]byte("grpc"), 40000)
			go func() {
				defer pw.Close()
				for off := 0; off < len(payload); {
					n := min(10000, len(payload)-off)
					b := grpcMessage(payload[off : off+n])
					if mode == "TunMulti" {
						b = grpcMessage(payload[off:off+n/2], payload[off+n/2:off+n])
					}
					if _, e := pw.Write(b); e != nil {
						return
					}
					off += n
				}
			}()
			p := make([]byte, len(payload))
			if _, e = io.ReadFull(decoded, p); e != nil || !bytes.Equal(p, payload) {
				t.Fatal("gRPC bytes", e)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			if response.Trailer.Get("Grpc-Status") != "0" {
				t.Fatal(response.Trailer)
			}
		})
	}
}
func TestProtoFixedFixtureAndLimits(t *testing.T) {
	b, e := hex.DecodeString("0a036162630a0264651001")
	if e != nil {
		t.Fatal(e)
	}
	for _, multi := range []bool{false, true} {
		sp, e := parseHunks(b, multi, 10)
		if e != nil {
			t.Fatal(e)
		}
		expected := "de"
		if multi {
			expected = "abcde"
		}
		if string(bytes.Join(sp, nil)) != expected {
			t.Fatal(sp)
		}
	}
	for _, b := range [][]byte{{0}, {0x0a, 8, 1}, {0x08, 1}, {0x0b}, {0x80}, {0x0a, 0x80}} {
		if _, e := parseHunks(b, true, 10); e == nil {
			t.Fatalf("invalid proto accepted %x", b)
		}
	}
	if _, e := parseHunks([]byte{10, 0, 10, 0}, true, 1); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	r := &grpcReader{r: bytes.NewReader([]byte{1, 0, 0, 0, 0}), max: 10, fields: 10}
	if _, e = r.Read(make([]byte, 1)); !errors.Is(e, ErrProtocol) {
		t.Fatal(e)
	}
}
func TestHTTPRejectAndEarlyDataNoGuessing(t *testing.T) {
	for _, kind := range []Kind{WebSocket, HTTPUpgrade, GRPC} {
		t.Run(string(kind), func(t *testing.T) {
			h := start(t, Config{Kind: kind, MaxEarlyData: map[Kind]int{WebSocket: 8}[kind]}, func(context.Context, *Stream, Metadata) error { t.Error("invalid request callback"); return nil })
			for _, pair := range []struct {
				path, host, extra string
				want              int
			}{{"/wrong", "vt.test", "", 404}, {"/tunnel", "wrong.test", "", 404}, {"/tunnel", "vt.test", "Sec-WebSocket-Protocol: YWJj, ZGVm\r\n", 400}} {
				if kind == GRPC && pair.want == 400 {
					continue
				}
				if kind == GRPC {
					tr := &http2.Transport{TLSClientConfig: h.clientTLS.Clone()}
					request, _ := http.NewRequest("POST", "https://"+h.addr+pair.path, bytes.NewReader(nil))
					request.Host = pair.host
					request.Header.Set("Content-Type", "application/grpc")
					resp, e := (&http.Client{Transport: tr, Timeout: time.Second}).Do(request)
					if e != nil || resp.StatusCode != pair.want {
						t.Fatal(resp, e, pair)
					}
					resp.Body.Close()
					tr.CloseIdleConnections()
					continue
				}
				c := h.dial(t)
				req := "GET " + pair.path + " HTTP/1.1\r\nHost: " + pair.host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" + pair.extra + "\r\n"
				c.Write([]byte(req))
				resp, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
				if e != nil || resp.StatusCode != pair.want {
					t.Fatal(resp, e, pair)
				}
				resp.Body.Close()
				c.Close()
			}
		})
	}
}

// RFC6455 mask/fragments are literal test-wire constructions, not a production
// websocket implementation. The mature library handles control/frame validation.
func masked(fin bool, opcode byte, p []byte) []byte {
	b := opcode
	if fin {
		b |= 128
	}
	out := []byte{b, 128 | byte(len(p)), 1, 2, 3, 4}
	for i, v := range p {
		out = append(out, v^byte(i%4+1))
	}
	return out
}
func TestRFC6455FragmentsPingAndTextRejected(t *testing.T) {
	h := start(t, Config{Kind: WebSocket, MaxMessageBytes: 128, WriteChunkBytes: 32}, echo)
	for _, text := range []bool{false, true} {
		c := h.dial(t)
		key := base64.StdEncoding.EncodeToString(make([]byte, 16))
		fmt.Fprintf(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", key)
		r := bufio.NewReader(c)
		resp, e := http.ReadResponse(r, &http.Request{Method: "GET"})
		if e != nil || resp.StatusCode != 101 {
			t.Fatal(resp, e)
		}
		if text {
			c.Write(masked(true, 1, []byte("text")))
			var hdr [2]byte
			_, e = io.ReadFull(r, hdr[:])
			if e == nil && hdr[0]&15 != 8 {
				t.Fatal("text accepted", hdr)
			}
			c.Close()
			continue
		}
		c.Write(append(append(masked(false, 2, []byte("abc")), masked(true, 9, []byte("p"))...), masked(true, 0, []byte("def"))...))
		var got []byte
		pong := false
		for len(got) < 6 {
			var hdr [2]byte
			if _, e = io.ReadFull(r, hdr[:]); e != nil {
				t.Fatal(e)
			}
			p := make([]byte, int(hdr[1]&127))
			io.ReadFull(r, p)
			if hdr[0]&15 == 10 {
				pong = true
			} else if hdr[0]&15 == 2 {
				got = append(got, p...)
			}
		}
		if string(got) != "abcdef" {
			t.Fatal(string(got))
		}
		if !pong {
			var hdr [2]byte
			io.ReadFull(r, hdr[:])
			p := make([]byte, int(hdr[1]&127))
			io.ReadFull(r, p)
			pong = hdr[0]&15 == 10
		}
		if !pong {
			t.Fatal("missing pong")
		}
		c.Close()
	}
}
