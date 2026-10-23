package vlessx

// RFC8446 test-only wire construction using public key logging and mature
// AEAD/HKDF primitives. No TLS implementation or cipher algorithm is copied.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func expandTLS(t *testing.T, h func() hash.Hash, secret []byte, label string, n int) []byte {
	t.Helper()
	s := []byte("tls13 " + label)
	info := append([]byte{byte(n >> 8), byte(n), byte(len(s))}, s...)
	info = append(info, 0)
	out := make([]byte, n)
	_, e := io.ReadFull(hkdf.Expand(h, secret, info), out)
	must(t, e)
	return out
}
func clientTraffic(t *testing.T, keylog string) []byte {
	t.Helper()
	for _, line := range strings.Split(keylog, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "CLIENT_TRAFFIC_SECRET_0" {
			b, e := hex.DecodeString(f[2])
			must(t, e)
			return b
		}
	}
	t.Fatal("no traffic secret")
	return nil
}
func sealTLS(t *testing.T, suite uint16, secret, p []byte) []byte {
	t.Helper()
	hf := sha256.New
	keyLen := 16
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		hf = sha512.New384
		keyLen = 32
	} else if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		keyLen = 32
	}
	key := expandTLS(t, hf, secret, "key", keyLen)
	iv := expandTLS(t, hf, secret, "iv", 12)
	var a cipher.AEAD
	var e error
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		a, e = chacha20poly1305.New(key)
	} else {
		block, err := aes.NewCipher(key)
		must(t, err)
		a, e = cipher.NewGCM(block)
	}
	must(t, e)
	n := len(p) + a.Overhead()
	header := []byte{23, 3, 3, byte(n >> 8), byte(n)}
	return a.Seal(header, iv, p, header)
}
func TestOuterKeyUpdateBeforeDirectAndFailClosedAfter(t *testing.T) {
	for _, afterDirect := range []bool{false, true} {
		name := "before-direct"
		if afterDirect {
			name = "after-output-direct-fail-closed"
		}
		t.Run(name, func(t *testing.T) {
			cert := certFor(t, "front.test")
			ln := tcpListen(t)
			defer ln.Close()
			done := make(chan error, 1)
			ready := make(chan struct{})
			go func() {
				raw, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				tr, e := AcceptTLS(context.Background(), raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				if e != nil {
					done <- e
					return
				}
				defer tr.Close()
				tr.SetDeadline(time.Now().Add(3 * time.Second))
				if afterDirect {
					e = tr.switchWrite()
					if e != nil {
						done <- e
						return
					}
				}
				close(ready)
				b := make([]byte, 5)
				_, e = io.ReadFull(tr, b)
				if afterDirect {
					if e == nil {
						done <- ErrWire
					} else {
						done <- nil
					}
					return
				}
				if e != nil {
					done <- e
					return
				}
				if string(b) != "probe" {
					done <- ErrWire
					return
				}
				e = writeFull(tr, []byte("reply"))
				if e == nil {
					e = tr.CloseWrite()
				}
				done <- e
			}()
			raw, e := net.Dial("tcp", ln.Addr().String())
			must(t, e)
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			var keylog bytes.Buffer
			cc := tls.Client(raw, &tls.Config{RootCAs: certRoots(t, cert), ServerName: "front.test", MinVersion: tls.VersionTLS13, KeyLogWriter: &keylog})
			must(t, cc.Handshake())
			<-ready
			secret := clientTraffic(t, keylog.String())
			suite := cc.ConnectionState().CipherSuite
			// First client application traffic record: KeyUpdate(request_update=1).
			must(t, writeFull(raw, sealTLS(t, suite, secret, []byte{24, 0, 0, 1, 1, 22})))
			if afterDirect {
				var b [1]byte
				_, e = cc.Read(b[:])
				if e == nil {
					t.Fatal("outer KU after raw direction silently accepted")
				}
				must(t, <-done)
				return
			}
			hf := sha256.New
			if suite == tls.TLS_AES_256_GCM_SHA384 {
				hf = sha512.New384
			}
			next := expandTLS(t, hf, secret, "traffic upd", hf().Size())
			must(t, writeFull(raw, sealTLS(t, suite, next, append([]byte("probe"), 23))))
			got, e := io.ReadAll(cc)
			must(t, e)
			if string(got) != "reply" {
				t.Fatal(string(got))
			}
			must(t, <-done)
			t.Log("TLS KeyUpdate processed and authenticated following record preserved")
		})
	}
}
