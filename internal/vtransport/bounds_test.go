package vtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"
)

func TestCertificateAndTestVLESSAuthRejection(t *testing.T) {
	var authenticated, early atomic.Int32
	h := start(t, Config{Kind: HTTPUpgrade}, basicVLESSEcho(&authenticated, &early))
	bad := h.clientTLS.Clone()
	bad.RootCAs = x509.NewCertPool()
	if c, e := tls.Dial("tcp", h.addr, bad); e == nil {
		c.Close()
		t.Fatal("untrusted certificate accepted")
	}
	c := h.dial(t)
	defer c.Close()
	fmt.Fprint(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	r := bufio.NewReader(c)
	response, e := http.ReadResponse(r, &http.Request{Method: "GET"})
	if e != nil || response.StatusCode != 101 {
		t.Fatal(response, e)
	}
	wrong := append([]byte{0}, make([]byte, 16)...)
	wrong = append(wrong, 0, 1, 1, 187, 1, 127, 0, 0, 1)
	c.Write(wrong)
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = r.ReadByte(); e == nil {
		t.Fatal("wrong VLESS UUID accepted")
	}
	if authenticated.Load() != 0 {
		t.Fatal("unauthenticated echo")
	}
}
func TestWebSocketMessageLimitAndInvalidEarlyData(t *testing.T) {
	result := make(chan error, 1)
	h := start(t, Config{Kind: WebSocket, MaxMessageBytes: 128, WriteChunkBytes: 32, MaxEarlyData: 8}, func(ctx context.Context, st *Stream, m Metadata) error {
		_, e := io.Copy(io.Discard, st)
		result <- e
		return e
	})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: h.clientTLS.Clone()}}
	ws, _, e := websocket.Dial(context.Background(), "wss://"+h.addr+"/tunnel", &websocket.DialOptions{Host: "vt.test", HTTPClient: client})
	if e != nil {
		t.Fatal(e)
	}
	defer ws.CloseNow()
	_ = ws.Write(context.Background(), websocket.MessageBinary, make([]byte, 256))
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("oversized WS message accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("WS limit not enforced")
	}
	for _, protocol := range []string{"not+raw/url==", "YWJj, ZGVm", "YWJjZGVmZ2hpag"} {
		c := h.dial(t)
		fmt.Fprintf(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: %s\r\n\r\n", protocol)
		r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if e != nil || r.StatusCode != 400 {
			t.Fatal(r, e)
		}
		r.Body.Close()
		c.Close()
	}
}
func TestBoundedHeadersIdleConnectionsAndCancel(t *testing.T) {
	h := start(t, Config{Kind: HTTPUpgrade, MaxConnections: 1, MaxHeaderBytes: 512, HeaderTimeout: 40 * time.Millisecond, IdleTimeout: 40 * time.Millisecond}, echo)
	first, e := net.Dial("tcp", h.addr)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	time.Sleep(5 * time.Millisecond)
	second, e := net.Dial("tcp", h.addr)
	if e == nil {
		second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var b [1]byte
		_, e = second.Read(b[:])
		second.Close()
		if e == nil {
			t.Fatal("connection budget not enforced")
		}
	}
	if h.s.Stats().Connections > 1 {
		t.Fatal(h.s.Stats())
	}
	time.Sleep(65 * time.Millisecond)
	first.Close()
	c := h.dial(t)
	defer c.Close()
	large := bytes.Repeat([]byte{'a'}, 6000)
	request := append([]byte("GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nX-Large: "), large...)
	request = append(request, []byte("\r\n\r\n")...)
	c.Write(request)
	r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if e == nil {
		if r.StatusCode != 431 {
			t.Fatal(r.Status)
		}
		r.Body.Close()
	}
	h.cancel()
}
func TestShutdownCancelsActiveStreamsAndBoundsBadCallback(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			h := start(t, Config{Kind: HTTPUpgrade, ShutdownTimeout: 40 * time.Millisecond}, func(ctx context.Context, st *Stream, m Metadata) error {
				close(entered)
				if bad {
					<-release
				} else {
					<-ctx.Done()
				}
				return nil
			})
			c := h.dial(t)
			defer c.Close()
			fmt.Fprint(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			resp, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
			if e != nil || resp.StatusCode != 101 {
				t.Fatal(resp, e)
			}
			<-entered
			h.cancel()
			e = <-h.done
			if bad {
				if !errors.Is(e, ErrShutdownTimeout) {
					t.Fatal(e)
				}
				close(release)
			} else if !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			h.done <- nil
			deadline := time.Now().Add(time.Second)
			for h.s.Stats().Streams > 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if h.s.Stats() != (Stats{}) {
				t.Fatal("quota leak", h.s.Stats())
			}
		})
	}
}
func TestGRPCMalformedFrameStatusAndBoundedProto(t *testing.T) {
	h := start(t, Config{Kind: GRPC, MaxMessageBytes: 128, WriteChunkBytes: 32}, echo)
	tr := &http2.Transport{TLSClientConfig: h.clientTLS.Clone()}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	for _, wire := range [][]byte{{1, 0, 0, 0, 0}, {0, 0, 0, 1, 0}, {0, 0, 0, 0, 2, 10}, {0, 0, 0, 0, 2, 10, 50}} {
		request, _ := http.NewRequest("POST", "https://"+h.addr+"/vt/Tun", bytes.NewReader(wire))
		request.Host = "vt.test"
		request.Header.Set("Content-Type", "application/grpc")
		request.Header.Set("Te", "trailers")
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.Trailer.Get("Grpc-Status") != "13" {
			t.Fatal(response.Trailer)
		}
	}
	raw := grpcMessage([]byte("x"))
	for cut := 1; cut < len(raw); cut++ {
		r := &grpcReader{r: bytes.NewReader(raw[:cut]), max: 128, fields: 10}
		if _, e := io.ReadAll(r); e == nil {
			t.Fatal("truncated gRPC accepted", cut)
		}
	}
	// Independent literal protobuf: two repeated bytes entries => concatenated multi.
	fixed := []byte{0, 0, 0, 0, 7, 10, 1, 'a', 10, 2, 'b', 'c'}
	r := &grpcReader{r: bytes.NewReader(fixed), max: 128, fields: 10, multi: true}
	p, e := io.ReadAll(r)
	if e != nil || string(p) != "abc" {
		t.Fatal(p, e)
	}
	if binary.BigEndian.Uint32(fixed[1:5]) != 7 {
		t.Fatal("fixture length")
	}
}

func TestStreamCapacityAndHalfCloseContract(t *testing.T) {
	for _, kind := range []Kind{WebSocket, HTTPUpgrade, GRPC} {
		t.Run(string(kind), func(t *testing.T) {
			if kind == GRPC {
				return
			}
			entered := make(chan *Stream, 1)
			h := start(t, Config{Kind: kind, MaxStreams: 1}, func(ctx context.Context, st *Stream, m Metadata) error { entered <- st; <-ctx.Done(); return nil })
			var first io.Closer
			if kind == WebSocket {
				client := &http.Client{Transport: &http.Transport{TLSClientConfig: h.clientTLS.Clone()}}
				ws, _, e := websocket.Dial(context.Background(), "wss://"+h.addr+"/tunnel", &websocket.DialOptions{Host: "vt.test", HTTPClient: client})
				if e != nil {
					t.Fatal(e)
				}
				first = &wsClose{ws}
			} else {
				c := h.dial(t)
				fmt.Fprint(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
				if e != nil || r.StatusCode != 101 {
					t.Fatal(r, e)
				}
				first = c
			}
			defer first.Close()
			st := <-entered
			if kind == WebSocket {
				if e := st.CloseWrite(); !errors.Is(e, ErrHalfCloseUnsupported) {
					t.Fatal(e)
				}
			}
			c := h.dial(t)
			defer c.Close()
			fmt.Fprint(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			r, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
			if e != nil || r.StatusCode != 503 {
				t.Fatal(r, e)
			}
			r.Body.Close()
			if h.s.Stats().Streams != 1 {
				t.Fatal(h.s.Stats())
			}
			h.cancel()
		})
	}
}

type wsClose struct{ c *websocket.Conn }

func (w *wsClose) Close() error { return w.c.CloseNow() }
func TestConfigHostPortAndLimits(t *testing.T) {
	for _, c := range []Config{{Kind: "unknown"}, {Kind: WebSocket, Path: "/x?ed=1"}, {Kind: GRPC, ServiceName: "/custom/path"}, {Kind: HTTPUpgrade, MaxEarlyData: 1}, {Kind: WebSocket, MaxEarlyData: -1}, {Kind: WebSocket, MaxStreams: -1}, {Kind: WebSocket, HTTP2StreamWindow: 1}} {
		if _, e := NewServer(c); !errors.Is(e, ErrConfig) {
			t.Fatal(c, e)
		}
	}
	if !equalHost("VT.TEST:443", "vt.test") || equalHost("vt.test:444", "vt.test:443") || !equalHost("VT.TEST:443", "vt.test:443") {
		t.Fatal("explicit authority policy")
	}
}

func TestUpgradeTrueTLSHalfCloseAndWriteDeadline(t *testing.T) {
	result := make(chan error, 1)
	h := start(t, Config{Kind: HTTPUpgrade}, func(ctx context.Context, st *Stream, m Metadata) error {
		if _, e := st.Write([]byte("hello")); e != nil {
			result <- e
			return e
		}
		if e := st.CloseWrite(); e != nil {
			result <- e
			return e
		}
		p := make([]byte, 4)
		_, e := io.ReadFull(st, p)
		if e == nil && string(p) != "tail" {
			e = ErrProtocol
		}
		result <- e
		return e
	})
	c := h.dial(t)
	defer c.Close()
	fmt.Fprint(c, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	r := bufio.NewReader(c)
	resp, e := http.ReadResponse(r, &http.Request{Method: "GET"})
	if e != nil || resp.StatusCode != 101 {
		t.Fatal(resp, e)
	}
	p, e := io.ReadAll(r)
	if e != nil || string(p) != "hello" {
		t.Fatal(string(p), e)
	}
	if _, e = c.Write([]byte("tail")); e != nil {
		t.Fatal(e)
	}
	if e = <-result; e != nil {
		t.Fatal("TLS CloseWrite destroyed read direction", e)
	}
	h2 := start(t, Config{Kind: HTTPUpgrade}, func(ctx context.Context, st *Stream, m Metadata) error {
		st.SetWriteDeadline(time.Now().Add(-time.Second))
		_, e := st.Write([]byte("forbidden"))
		result <- e
		return e
	})
	c2 := h2.dial(t)
	defer c2.Close()
	fmt.Fprint(c2, "GET /tunnel HTTP/1.1\r\nHost: vt.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	resp, e = http.ReadResponse(bufio.NewReader(c2), &http.Request{Method: "GET"})
	if e != nil || resp.StatusCode != 101 {
		t.Fatal(resp, e)
	}
	if e = <-result; e == nil {
		t.Fatal("expired write deadline ignored")
	}
}
