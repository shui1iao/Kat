package tlsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func serverCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "srv.example"}, DNSNames: []string{"srv.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestHandshakeFingerprints(t *testing.T) {
	cert, pool := serverCert(t)
	ln, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	pin := sha256.Sum256(cert.Certificate[0])
	pinCfg := func(want [32]byte) *tls.Config {
		return &tls.Config{ServerName: "srv.example", InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if sha256.Sum256(cs.PeerCertificates[0].Raw) != want {
				return errors.New("pin mismatch")
			}
			return nil
		}}
	}
	for _, fp := range append([]string{""}, Fingerprints...) {
		for _, tc := range []struct {
			name string
			cfg  *tls.Config
			ok   bool
			alpn string
		}{
			{"roots", &tls.Config{ServerName: "srv.example", RootCAs: pool}, true, ""},
			{"alpn", &tls.Config{ServerName: "srv.example", RootCAs: pool, NextProtos: []string{"http/1.1"}}, true, "http/1.1"},
			{"wrong-name", &tls.Config{ServerName: "other.example", RootCAs: pool}, false, ""},
			{"system-roots", &tls.Config{ServerName: "srv.example"}, false, ""},
			{"pin", pinCfg(pin), true, ""},
			{"bad-pin", pinCfg([32]byte{1}), false, ""},
		} {
			raw, e := net.Dial("tcp", ln.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			c, e := Handshake(ctx, raw, tc.cfg, fp)
			cancel()
			if (e == nil) != tc.ok {
				t.Fatalf("fp %q %s: err %v", fp, tc.name, e)
			}
			if e == nil {
				if tc.alpn != "" && fp != "android" { // the OkHttp profile sends no ALPN
					var got string
					switch x := c.(type) {
					case *tls.Conn:
						got = x.ConnectionState().NegotiatedProtocol
					case *utls.UConn:
						got = x.ConnectionState().NegotiatedProtocol
					}
					if got != tc.alpn {
						t.Fatalf("fp %q: ALPN %q", fp, got)
					}
				}
				c.Write([]byte("x"))
				b := make([]byte, 1)
				if _, e := io.ReadFull(c, b); e != nil || b[0] != 'x' {
					t.Fatalf("fp %q %s: echo %v", fp, tc.name, e)
				}
				if cw, ok := c.(interface{ CloseWrite() error }); !ok {
					t.Fatalf("fp %q: no CloseWrite", fp)
				} else {
					_ = cw
				}
				c.Close()
			}
			raw.Close()
		}
	}
	if Validate("netscape") == nil || Validate("chrome") != nil || Validate("") != nil {
		t.Fatal("Validate")
	}
	if r := Resolved("random"); r == "random" || r == "" || Resolved("random") != r {
		t.Fatal("random resolution", r)
	}
}
