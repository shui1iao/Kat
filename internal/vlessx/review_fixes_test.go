// Regression cases derived from the independent review PoCs; expected results
// changed from reproducing defects to preserving successful TLS behavior.
package vlessx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func reviewConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
}

type reviewSplitConn struct {
	net.Conn
	arm          atomic.Bool
	sent, resume chan struct{}
	prefix       int
}

func (c *reviewSplitConn) Write(p []byte) (int, error) {
	if c.arm.CompareAndSwap(true, false) && len(p) > c.prefix {
		n, e := c.Conn.Write(p[:c.prefix])
		if e != nil {
			return n, e
		}
		close(c.sent)
		<-c.resume
		k, e := c.Conn.Write(p[c.prefix:])
		return n + k, e
	}
	return c.Conn.Write(p)
}
func reviewPair(t *testing.T, callback bool, contexts ...context.Context) (*Transport, *tls.Conn, *reviewSplitConn) {
	t.Helper()
	sc, cc := reviewConfigs(t)
	if callback {
		returned := sc.Clone() // ordinary callback result retains default adaptive record sizing
		sc.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return returned, nil }
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	raw, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	srv, e := ln.Accept()
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	split := &reviewSplitConn{Conn: raw, sent: make(chan struct{}), resume: make(chan struct{}), prefix: 2}
	cl := tls.Client(split, cc)
	done := make(chan error, 1)
	go func() { done <- cl.Handshake() }()
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	tr, e := AcceptTLS(ctx, srv, sc)
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		tr.Close()
		raw.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { tr.Close(); raw.Close() })
	return tr, cl, split
}

// This targets the unmodified final-record seam, not the author test matrix.
// The buffer length is a reachable Vision final-block length; this does not
// claim to reproduce an inner TLS handshake or bypass VLESS authorization.
func TestReviewFinalRecordConfigCallback(t *testing.T) {
	for _, callback := range []bool{false, true} {
		name := "ordinary-config"
		if callback {
			name = "GetConfigForClient"
		}
		t.Run(name, func(t *testing.T) {
			tr, cl, _ := reviewPair(t, callback)
			p := make([]byte, 4000)
			p[0] = 2
			p[1] = byte(3995 >> 8)
			p[2] = byte(3995 & 255)
			readDone := make(chan error, 1)
			go func() {
				b := make([]byte, len(p))
				_, e := io.ReadFull(cl, b)
				if e == nil && !bytes.Equal(b, p) {
					e = errors.New("plaintext mismatch")
				}
				readDone <- e
			}()
			e := tr.writeFinalVision(p)
			re := <-readDone
			t.Logf("callback=%v final_plaintext=%d write_err=%v peer_read_err=%v", callback, len(p), e, re)
			if !callback && (e != nil || re != nil) {
				t.Fatalf("control failed: %v / %v", e, re)
			}
			if e != nil || re != nil {
				t.Fatalf("valid final record must succeed: %v / %v", e, re)
			}
			if !tr.gate.writeDirect || !tr.wd {
				t.Fatal("final switch not committed")
			}
		})
	}
}

func TestReviewHeaderDeadlineResume(t *testing.T) {
	for _, prefix := range []int{1, 2, 3, 4, 6, 12} {
		t.Run(fmt.Sprintf("prefix-%d", prefix), func(t *testing.T) {
			tr, cl, split := reviewPair(t, false)
			split.prefix = prefix
			split.arm.Store(true)
			want := []byte("authenticated TLS plaintext after resumed header/body")
			writeDone := make(chan error, 1)
			go func() { _, e := cl.Write(want); writeDone <- e }()
			<-split.sent
			tr.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			b := make([]byte, 128)
			n, e := tr.Read(b)
			ne, ok := e.(net.Error)
			if !ok || !ne.Timeout() {
				close(split.resume)
				t.Fatalf("expected timeout n=%d e=%v", n, e)
			}
			tr.SetReadDeadline(time.Time{})
			close(split.resume)
			n, e = io.ReadFull(tr, b[:len(want)])
			we := <-writeDone
			t.Logf("prefix=%d resumed_n=%d read_err=%v write_err=%v match=%v", prefix, n, e, we, bytes.Equal(b[:n], want))
			if e != nil || we != nil || !bytes.Equal(b[:n], want) {
				t.Fatalf("deadline recovery lost bytes: %v / %v", e, we)
			}
			if tr.gate.have != 0 || tr.gate.remaining != 0 {
				t.Fatal("record boundary lost")
			}
		})
	}
}
func TestReviewNoTimeoutFragmentation(t *testing.T) {
	for _, prefix := range []int{1, 2, 3, 4, 6, 12} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			tr, cl, split := reviewPair(t, false)
			split.prefix = prefix
			split.arm.Store(true)
			want := bytes.Repeat([]byte{0x61}, 97)
			done := make(chan error, 1)
			go func() { _, e := cl.Write(want); done <- e }()
			<-split.sent
			go func() { time.Sleep(time.Millisecond); close(split.resume) }()
			got := make([]byte, len(want))
			_, e := io.ReadFull(tr, got)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestReviewPartialHeaderCancel(t *testing.T) {
	for _, prefix := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tr, cl, split := reviewPair(t, false, ctx)
			split.prefix = prefix
			split.arm.Store(true)
			writeDone := make(chan error, 1)
			go func() { _, e := cl.Write([]byte("blocked")); writeDone <- e }()
			<-split.sent
			readDone := make(chan error, 1)
			go func() { _, e := tr.Read(make([]byte, 8)); readDone <- e }()
			cancel()
			select {
			case e := <-readDone:
				if e == nil {
					t.Fatal("closed read succeeded")
				}
			case <-time.After(time.Second):
				close(split.resume)
				<-writeDone
				t.Fatal("Close did not release partial header")
			}
			close(split.resume)
			<-writeDone
		})
	}
}

func TestReviewConfigCallbackSemantics(t *testing.T) {
	base, _ := reviewConfigs(t)
	returned := base.Clone()
	callbackErr := errors.New("callback sentinel")
	for _, mode := range []string{"new-config", "nil-config", "error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			input := base.Clone()
			input.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				calls++
				if h.ServerName != "expected.sni" {
					t.Fatal(h.ServerName)
				}
				switch mode {
				case "nil-config":
					return nil, nil
				case "error":
					return nil, callbackErr
				default:
					return returned, nil
				}
			}
			configured := cloneTLSConfigForGate(input)
			if input.DynamicRecordSizingDisabled || returned.DynamicRecordSizingDisabled {
				t.Fatal("caller config mutated")
			}
			if !configured.DynamicRecordSizingDisabled {
				t.Fatal("outer clone missing invariant")
			}
			result, e := configured.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "expected.sni"})
			if calls != 1 {
				t.Fatal(calls)
			}
			switch mode {
			case "new-config":
				if e != nil || result == returned || !result.DynamicRecordSizingDisabled || len(result.Certificates) != len(returned.Certificates) {
					t.Fatal("callback result not preserved/cloned", e)
				}
			case "nil-config":
				if e != nil || result != nil {
					t.Fatal("nil fallback changed")
				}
			case "error":
				if e != callbackErr || result != nil {
					t.Fatal("error identity changed")
				}
			}
			if input.DynamicRecordSizingDisabled || returned.DynamicRecordSizingDisabled {
				t.Fatal("caller mutated after callback")
			}
		})
	}
}
func TestReviewPartialHeaderCannotSwitch(t *testing.T) {
	m := &memoryConn{Reader: bytes.NewReader(nil)}
	gate := &recordGate{ownedConn: &ownedConn{Conn: m, done: make(chan struct{})}, headerRead: 2}
	tr := &Transport{gate: gate}
	if e := tr.switchRead(); e != ErrState {
		t.Fatal("partial header treated as raw boundary", e)
	}
}
