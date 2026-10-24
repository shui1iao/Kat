package kernel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

// UnmarshalJSON decodes one inbound exactly like the plain struct (unknown
// fields rejected) and additionally records whether a "tls" member was
// written at all. An AnyTLS inbound that omits "tls" gets an ephemeral
// in-memory certificate; one that writes "tls" (including null) keeps the
// strict cert/key rules. Key matching follows encoding/json (case-insensitive).
func (in *Inbound) UnmarshalJSON(b []byte) error {
	type plain Inbound
	var p plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return e
	}
	var m map[string]json.RawMessage
	if e := json.Unmarshal(b, &m); e != nil {
		return e
	}
	for k := range m {
		if strings.EqualFold(k, "tls") {
			p.tlsWritten = true
		}
	}
	*in = Inbound(p)
	return nil
}

// ephemeralTLSConfig returns a server TLS configuration holding a freshly
// generated self-signed ECDSA P-256 certificate. Nothing is written to disk.
// The names are a neutral fixed value: no host name, address or product
// string. TLS parameters match the file-certificate path for AnyTLS.
func ephemeralTLSConfig(now time.Time) (*tls.Config, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if e != nil {
		return nil, e
	}
	serial.Add(serial, big.NewInt(1)) // positive, at most 16 bytes
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
