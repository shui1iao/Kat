package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func inlineTLS(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	client, e := net.Dial("tcp4", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := ln.Accept()
	if e != nil {
		t.Fatal(e)
	}
	raw.(*net.TCPConn).SetWriteBuffer(1024)
	server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
	peer := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	if e = peer.Handshake(); e != nil {
		t.Fatal(e)
	}
	if e = <-errc; e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { server.Close(); peer.Close() })
	return server, peer
}
func TestOwnedInlineTLSWithoutWriterAndFullClear(t *testing.T) {
	tr, peer := inlineTLS(t)
	s, st := ownedSession(t, tr, time.Second)
	wire := bytes.Repeat([]byte{0x44}, 32775)
	wire = wire[:1007]
	received := make(chan []byte, 1)
	go func() {
		b := make([]byte, len(wire))
		_, e := io.ReadFull(peer, b)
		if e != nil {
			t.Error(e)
		}
		received <- b
	}()
	var count atomic.Int32
	n, e := st.WriteOwnedFrame(wire, func(b []byte) {
		count.Add(1)
		if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
			t.Error("partial clear")
		}
		if s.outBytes != 32775 {
			t.Error("early budget release")
		}
	})
	if e != nil || n != 1000 || count.Load() != 1 {
		t.Fatal(n, e, count.Load())
	}
	got := <-received
	if got[0] != cmdPSH || !bytes.Equal(got[7:], bytes.Repeat([]byte{0x44}, 1000)) {
		t.Fatal("wire corruption")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeWriter != nil || s.outBytes != 0 || s.outFrames != 0 || len(s.out) != 0 {
		t.Fatal("leaked ownership")
	}
}
func TestOwnedInlineTLSConcurrentSingleWriter(t *testing.T) {
	tr, peer := inlineTLS(t)
	s, _ := ownedSession(t, tr, 2*time.Second)
	go s.writeLoop()
	var wg sync.WaitGroup
	const n = 16
	errc := make(chan error, n)
	go func() {
		for i := 0; i < n; i++ {
			b := make([]byte, 1007)
			if _, e := io.ReadFull(peer, b); e != nil {
				errc <- e
				return
			}
			for _, v := range b[7:] {
				if v != b[7] {
					errc <- io.ErrUnexpectedEOF
					return
				}
			}
		}
		errc <- nil
	}()
	var released atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := &Stream{session: s, id: uint32(i + 1)}
			b := bytes.Repeat([]byte{byte(i + 10)}, 32775)
			_, e := st.WriteOwnedFrame(b[:1007], func(b []byte) {
				released.Add(1)
				if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
					t.Error("not clear")
				}
			})
			if e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	if e := <-errc; e != nil {
		t.Fatal(e)
	}
	s.fail(context.Canceled)
	<-s.writerDone
	if released.Load() != n {
		t.Fatal("release mismatch")
	}
	if s.outBytes != 0 || s.outFrames != 0 {
		t.Fatal("charge leak")
	}
}
func TestOwnedInlineTLSBlockedWriteTimeout(t *testing.T) {
	tr, peer := inlineTLS(t)
	_ = peer
	s, st := ownedSession(t, tr, 40*time.Millisecond)
	start := time.Now()
	var released atomic.Int32
	var writes int
	for ; writes < 1024; writes++ {
		b := bytes.Repeat([]byte{0x77}, 32775)
		_, e := st.WriteOwnedFrame(b, func(b []byte) {
			released.Add(1)
			if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
				t.Error("not fully cleared")
			}
		})
		if e != nil {
			break
		}
	}
	if writes == 1024 {
		t.Fatal("TCP did not backpressure")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout failed")
	}
	if released.Load() != int32(writes+1) || s.outBytes != 0 || s.outFrames != 0 || s.activeWriter != nil {
		t.Fatal("late writer ownership leaked")
	}
}

// A shutdown queue is not the transport owner. In particular its last frame
// cannot mark a concurrently completing inline write as idle or release its budget.
func TestOwnedInlineQueueCleanupCannotReleaseOtherIOOwner(t *testing.T) {
	tr, _ := inlineTLS(t)
	s, _ := ownedSession(t, tr, time.Second)
	active := &outbound{wire: bytes.Repeat([]byte{0x44}, 32775), cost: 32775, done: make(chan error, 1)}
	queued := &outbound{wire: bytes.Repeat([]byte{0x22}, 15), cost: 15, done: make(chan error, 1)}
	s.activeWriter = active
	s.outFrames = 2
	s.outBytes = 32790
	s.releaseOutbound(queued, context.Canceled)
	if s.activeWriter != active || s.outBytes != 32775 || s.outFrames != 1 {
		t.Fatal("queue teardown stole active ownership")
	}
	if active.wire[0] != 0x44 {
		t.Fatal("active memory prematurely cleared")
	}
	s.releaseOutbound(active, nil)
	if s.activeWriter != nil || s.outBytes != 0 || s.outFrames != 0 {
		t.Fatal("actual owner did not release")
	}
}
func TestOwnedInlineMixedControlFramesDoNotInterleave(t *testing.T) {
	tr, peer := inlineTLS(t)
	s, _ := ownedSession(t, tr, 2*time.Second)
	go s.writeLoop()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 32; i++ {
			h := make([]byte, 7)
			if _, e := io.ReadFull(peer, h); e != nil {
				done <- e
				return
			}
			n := int(h[5])<<8 | int(h[6])
			if (h[0] != cmdPSH || n != 1000) && (h[0] != cmdHeartRequest || n != 3) {
				done <- io.ErrUnexpectedEOF
				return
			}
			b := make([]byte, n)
			if _, e := io.ReadFull(peer, b); e != nil {
				done <- e
				return
			}
			for _, v := range b {
				if v != b[0] {
					done <- io.ErrUnexpectedEOF
					return
				}
			}
		}
		done <- nil
	}()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			st := &Stream{session: s, id: uint32(i + 1)}
			_, e := st.WriteOwnedFrame(bytes.Repeat([]byte{byte(i + 7)}, 1007), nil)
			if e != nil {
				t.Error(e)
			}
		}(i)
		go func() {
			defer wg.Done()
			if e := s.send(cmdHeartRequest, 0, []byte{9, 9, 9}, nil, time.Time{}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	s.fail(context.Canceled)
	select {
	case <-s.writerDone:
	case <-time.After(time.Second):
		t.Fatal("writer exit missing")
	}
	if s.activeWriter != nil || s.outBytes != 0 || s.outFrames != 0 {
		t.Fatal("sender join left owner")
	}
}
