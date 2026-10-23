package kernel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	VX "github.com/shui1iao/Kat/internal/vlessx"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestVLESSStaticTLSPathAndCallbacks(t *testing.T) {
	cert, pool := testCert(t)
	pair, e := tls.LoadX509KeyPair(cert.Cert, cert.Key)
	if e != nil {
		t.Fatal(e)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, kind := range []string{"ordinary", "vision", "mixed"} {
			in := inFor("vless", cert)
			switch kind {
			case "vision":
				in.Users[0].Flow = VX.VisionFlow
			case "mixed":
				in.Users = append(in.Users, User{UUID: "31004faa-7f59-47a6-8cbe-012345678901", Flow: VX.VisionFlow})
			}
			var callbacks atomic.Int64
			returned := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: version, MaxVersion: version, NextProtos: []string{"path-proof"}}
			original := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: version, MaxVersion: version, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				if h.ServerName != "localhost" {
					return nil, errors.New("bad SNI")
				}
				callbacks.Add(1)
				return returned, nil
			}}
			in.tlsConfig = original
			a, b := net.Pipe()
			a.SetDeadline(time.Now().Add(2 * time.Second))
			b.SetDeadline(time.Now().Add(2 * time.Second))
			client := tls.Client(b, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: version, MaxVersion: version, NextProtos: []string{"path-proof"}})
			type result struct {
				c  net.Conn
				tr *VX.Transport
				e  error
			}
			done := make(chan result, 1)
			go func() { c, tr, e := acceptVLESSRawTransport(context.Background(), a, in); done <- result{c, tr, e} }()
			if e = client.Handshake(); e != nil {
				t.Fatal(kind, version, e)
			}
			r := <-done
			if r.e != nil {
				t.Fatal(r.e)
			}
			_, plain := r.c.(*tls.Conn)
			if plain != (kind == "ordinary") || ((r.tr != nil) != (kind != "ordinary")) {
				t.Fatal("wrong static path", kind, version, plain, r.tr != nil)
			}
			if callbacks.Load() != 1 || client.ConnectionState().NegotiatedProtocol != "path-proof" || original.DynamicRecordSizingDisabled || returned.DynamicRecordSizingDisabled {
				t.Fatal("callback/ALPN/config clone changed")
			}
			payload := bytes.Repeat([]byte{0x43}, 32768)
			sent := make(chan error, 1)
			go func() { _, e := client.Write(payload); sent <- e }()
			got := make([]byte, len(payload))
			if _, e = io.ReadFull(r.c, got); e != nil || !bytes.Equal(got, payload) {
				t.Fatal("path data", kind, e)
			}
			if e = <-sent; e != nil {
				t.Fatal(e)
			}
			a.Close()
			b.Close()
			if r.tr != nil {
				r.tr.Close()
			}
		}
	}
	if !vlessTLSNeedsGate(nil) || !vlessTLSNeedsGate([]User{{Flow: "future-unknown-flow"}}) {
		t.Fatal("unknown/empty config failed open")
	}
}
func TestVLESSOrdinaryTLSRejectsBeforeTargetDial(t *testing.T) {
	cert, pool := testCert(t)
	var dials atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { dials.Add(1) })
	s := startTest(t, inFor("vless", cert), nil)
	header := flowHeader(1, target, "")
	seed := append(append([]byte(nil), header[:17]...), 3, 0x12, 1, 0x71)
	seed = append(seed, header[18:]...)
	badUUID := bytes.Clone(header)
	badUUID[1] ^= 0x11
	for _, raw := range [][]byte{badUUID, seed, flowHeader(1, target, VX.VisionFlow), flowHeader(7, target, ""), flowHeader(2, target, VX.VisionFlow)} {
		c := dialPeer(t, s, pool)
		_ = writeAll(c, raw)
		_ = c.(interface{ CloseWrite() error }).CloseWrite()
		got, _ := io.ReadAll(c)
		c.Close()
		if len(got) != 0 {
			t.Fatal("unauthorized returned data")
		}
	}
	for _, roots := range []*x509.CertPool{x509.NewCertPool(), pool} {
		name := "localhost"
		if roots == pool {
			name = "wrong.invalid"
		}
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13})
		if e == nil {
			c.Close()
			t.Fatal("untrusted CA/SNI accepted")
		}
	}
	if dials.Load() != 0 {
		t.Fatal("invalid identity/flow/Seed/command/trust dialed target", dials.Load())
	}
}
func TestVLESSOrdinaryTLSServerFirstFragmentedHalfCloseTail(t *testing.T) {
	cert, pool := testCert(t)
	payload := bytes.Repeat([]byte{0x39}, 257)
	tail := bytes.Repeat([]byte{0x63}, 512*1024)
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		_ = writeAll(c, []byte("server-first"))
		got, _ := io.ReadAll(c)
		if !bytes.Equal(got, payload) {
			t.Error("halfclose input mismatch")
		}
		_ = writeAll(c, tail)
	})
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		s := startTest(t, inFor("vless", cert), nil)
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: version, MaxVersion: version})
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(4 * time.Second))
		header := flowHeader(1, target, "")
		for _, b := range header {
			if e = writeAll(c, []byte{b}); e != nil {
				t.Fatal(e)
			}
		}
		prefix := make([]byte, 2+len("server-first"))
		if _, e = io.ReadFull(c, prefix); e != nil || !bytes.Equal(prefix, append([]byte{0, 0}, []byte("server-first")...)) {
			t.Fatal("first data", e)
		}
		if e = writeAll(c, payload); e != nil {
			t.Fatal(e)
		}
		if e = c.CloseWrite(); e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(c)
		if e != nil || !bytes.Equal(got, tail) {
			t.Fatal("512KiB reverse EOF tail", version, len(got), e)
		}
		c.Close()
		waitFor(t, func() bool { return s.Stats().Active == 0 && s.Stats().Handshakes == 0 })
	}
}
func TestVLESSOrdinaryTLSCancelHandshake(t *testing.T) {
	cert, _ := testCert(t)
	pair, e := tls.LoadX509KeyPair(cert.Cert, cert.Key)
	if e != nil {
		t.Fatal(e)
	}
	in := inFor("vless", cert)
	in.tlsConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, e := acceptVLESSRawTransport(ctx, a, in); done <- e }()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancel accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake cancellation did not unblock")
	}
}
