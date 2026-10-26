// Package tlscert provides the server certificates of Kat's TLS inbounds:
// certificate/key file pairs that can follow changes made by an external
// program, selection among several certificates by SNI, and certificates
// obtained and renewed through ACME (manager.go).
//
// A certificate is always replaced as a whole through an atomic pointer:
// handshakes in progress keep the certificate they started with and
// established connections are never touched.
package tlscert

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// maxFileBytes bounds every certificate, key or token file read.
const maxFileBytes = 1 << 20

// ErrLoad is returned (wrapped) when a certificate/key pair cannot be used.
var ErrLoad = errors.New("cannot load TLS certificate/key")

// ReadFileLimited reads a small file, refusing files above 1 MiB.
func ReadFileLimited(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > maxFileBytes {
		return nil, errors.New("file exceeds 1 MiB")
	}
	return b, nil
}

// ParsePair parses a PEM certificate chain and private key. The leaf is
// parsed and kept in Certificate.Leaf.
func ParsePair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	c, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		return nil, e
	}
	if c.Leaf == nil {
		leaf, e := x509.ParseCertificate(c.Certificate[0])
		if e != nil {
			return nil, e
		}
		c.Leaf = leaf
	}
	return &c, nil
}

func pairSum(certPEM, keyPEM []byte) [32]byte {
	h := sha256.New()
	h.Write(certPEM)
	h.Write([]byte{0})
	h.Write(keyPEM)
	var s [32]byte
	copy(s[:], h.Sum(nil))
	return s
}

// LoadPair reads and parses a certificate/key file pair.
func LoadPair(certFile, keyFile string) (*tls.Certificate, [32]byte, error) {
	cb, e := ReadFileLimited(certFile)
	if e != nil {
		return nil, [32]byte{}, ErrLoad
	}
	kb, e := ReadFileLimited(keyFile)
	if e != nil {
		return nil, [32]byte{}, ErrLoad
	}
	c, e := ParsePair(cb, kb)
	if e != nil {
		return nil, [32]byte{}, ErrLoad
	}
	return c, pairSum(cb, kb), nil
}

// Source provides a certificate; nil means "not available yet".
type Source interface {
	Certificate() *tls.Certificate
}

// Holder is an atomically replaced certificate.
type Holder struct {
	p atomic.Pointer[tls.Certificate]
}

func (h *Holder) Certificate() *tls.Certificate { return h.p.Load() }
func (h *Holder) Store(c *tls.Certificate)      { h.p.Store(c) }

// FilePair is a certificate loaded from a cert/key file pair. Check reads the
// files again and installs a changed, valid pair; an invalid one is refused
// and the previous certificate stays in use.
type FilePair struct {
	Holder
	CertFile, KeyFile string

	sum    atomic.Pointer[[32]byte] // content of the installed pair
	badSum [32]byte                 // content last refused (reported once)
	hasBad bool
	readOK bool // false after a read error was reported
}

// NewFilePair returns a pair holding an already loaded certificate.
func NewFilePair(certFile, keyFile string, c *tls.Certificate, sum [32]byte) *FilePair {
	f := &FilePair{CertFile: certFile, KeyFile: keyFile, readOK: true}
	f.sum.Store(&sum)
	f.Store(c)
	return f
}

// Sum identifies the content of the installed pair.
func (f *FilePair) Sum() [32]byte { return *f.sum.Load() }

// CheckResult is the outcome of one FilePair.Check.
type CheckResult int

const (
	Unchanged CheckResult = iota // same content, or a refusal already reported
	Replaced                     // a new valid certificate is in use
	Refused                      // new content is invalid: previous certificate kept
)

// SettleDelay is waited once before a changed pair that does not parse is
// read again (an external program may write the certificate and the key in
// two steps). Tests shorten it.
var SettleDelay = time.Second

// Check is called by one goroutine at a time (the watcher). now is used to
// refuse an already expired certificate.
func (f *FilePair) Check(now time.Time) (CheckResult, error) {
	var c *tls.Certificate
	var sum [32]byte
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		sum = [32]byte{}
		cb, e1 := ReadFileLimited(f.CertFile)
		kb, e2 := ReadFileLimited(f.KeyFile)
		if e1 != nil || e2 != nil {
			err = errors.New("cannot read certificate or key file")
		} else {
			sum = pairSum(cb, kb)
			if sum == f.Sum() {
				f.hasBad, f.readOK = false, true
				return Unchanged, nil
			}
			if f.hasBad && sum == f.badSum {
				return Unchanged, nil
			}
			c, err = ParsePair(cb, kb)
			if err == nil && now.After(c.Leaf.NotAfter) {
				err = errors.New("certificate has expired")
			}
			if err == nil {
				break
			}
		}
		if attempt == 0 && SettleDelay > 0 {
			time.Sleep(SettleDelay)
		}
	}
	if err != nil {
		if sum == ([32]byte{}) {
			// Read error: report once until the files can be read again.
			if !f.readOK {
				return Unchanged, nil
			}
			f.readOK = false
			return Refused, err
		}
		f.readOK = true
		f.badSum, f.hasBad = sum, true
		return Refused, err
	}
	f.Store(c)
	f.sum.Store(&sum)
	f.hasBad, f.readOK = false, true
	return Replaced, nil
}

// Selector picks the certificate for a ClientHello: the first source whose
// certificate covers the SNI name, else the default (the first source that
// currently has a certificate), else Fallback.
type Selector struct {
	Sources  []Source
	Fallback *tls.Certificate
}

// Pick returns the certificate for server name sni (may be empty).
func (s *Selector) Pick(sni string) *tls.Certificate {
	name := strings.ToLower(strings.TrimSuffix(sni, "."))
	var def *tls.Certificate
	for _, src := range s.Sources {
		c := src.Certificate()
		if c == nil {
			continue
		}
		if def == nil {
			def = c
			if name == "" {
				return c
			}
		}
		if name != "" && c.Leaf != nil && c.Leaf.VerifyHostname(name) == nil {
			return c
		}
	}
	if def == nil {
		return s.Fallback
	}
	return def
}

// PickHello is Pick for a handshake: among the certificates covering the
// SNI name (else among all, starting with the default) it prefers the first
// one the client supports (key type, signature schemes, TLS 1.2 suites),
// so that an ECDSA and an RSA certificate can serve the same name.
func (s *Selector) PickHello(h *tls.ClientHelloInfo) *tls.Certificate {
	name := strings.ToLower(strings.TrimSuffix(h.ServerName, "."))
	var named, all []*tls.Certificate
	for _, src := range s.Sources {
		c := src.Certificate()
		if c == nil {
			continue
		}
		all = append(all, c)
		if name != "" && c.Leaf != nil && c.Leaf.VerifyHostname(name) == nil {
			named = append(named, c)
		}
	}
	cands := named
	if len(cands) == 0 {
		cands = all
	}
	for _, c := range cands {
		if h.SupportsCertificate(c) == nil {
			return c
		}
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return s.Fallback
}

// SamePEM reports whether two certificates have the same DER chain.
func SamePEM(a, b *tls.Certificate) bool {
	if a == nil || b == nil || len(a.Certificate) != len(b.Certificate) {
		return a == b
	}
	for i := range a.Certificate {
		if !bytes.Equal(a.Certificate[i], b.Certificate[i]) {
			return false
		}
	}
	return true
}
