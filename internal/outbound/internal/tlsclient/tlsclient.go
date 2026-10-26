// Package tlsclient performs the client TLS handshake of the Trojan and
// AnyTLS outbounds, either with crypto/tls or, when a fingerprint is
// configured, with uTLS imitating a browser ClientHello.
package tlsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Fingerprints lists the accepted tls.fingerprint values.
var Fingerprints = []string{"chrome", "firefox", "safari", "ios", "edge", "android", "360", "qq", "random"}

// randomPool is what "random" picks from, once per process.
var randomPool = []string{"chrome", "firefox", "safari", "ios", "edge"}

var (
	randomOnce sync.Once
	randomPick string
)

// Validate accepts "" (crypto/tls) or one of Fingerprints.
func Validate(fp string) error {
	if fp == "" {
		return nil
	}
	if _, ok := helloID(fp); !ok {
		return errors.New("unknown tls.fingerprint")
	}
	return nil
}

func helloID(fp string) (utls.ClientHelloID, bool) {
	if fp == "random" {
		randomOnce.Do(func() { randomPick = randomPool[rand.IntN(len(randomPool))] })
		fp = randomPick
	}
	switch fp {
	case "chrome":
		return utls.HelloChrome_Auto, true
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "ios":
		return utls.HelloIOS_Auto, true
	case "edge":
		return utls.HelloEdge_Auto, true
	case "android":
		return utls.HelloAndroid_11_OkHttp, true
	case "360":
		return utls.Hello360_Auto, true
	case "qq":
		return utls.HelloQQ_Auto, true
	}
	return utls.ClientHelloID{}, false
}

// Resolved returns the concrete fingerprint "random" stands for in this
// process (other values are returned unchanged).
func Resolved(fp string) string {
	if fp == "random" {
		helloID(fp)
		return randomPick
	}
	return fp
}

// Handshake runs the client handshake over raw with cfg. With a
// fingerprint, cfg's server name, roots, verification mode (including a
// VerifyConnection pin), minimum version and ALPN are carried over to uTLS;
// a configured ALPN list replaces the one of the browser profile. The
// returned connection supports CloseWrite.
func Handshake(ctx context.Context, raw net.Conn, cfg *tls.Config, fp string) (net.Conn, error) {
	if fp == "" {
		c := tls.Client(raw, cfg)
		if e := c.HandshakeContext(ctx); e != nil {
			return nil, e
		}
		return c, nil
	}
	id, ok := helloID(fp)
	if !ok {
		return nil, errors.New("unknown tls.fingerprint")
	}
	uc := &utls.Config{ServerName: cfg.ServerName, RootCAs: cfg.RootCAs, InsecureSkipVerify: cfg.InsecureSkipVerify, MinVersion: cfg.MinVersion, NextProtos: cfg.NextProtos}
	if v := cfg.VerifyConnection; v != nil {
		uc.VerifyConnection = func(cs utls.ConnectionState) error {
			return v(tls.ConnectionState{Version: cs.Version, HandshakeComplete: cs.HandshakeComplete, DidResume: cs.DidResume, CipherSuite: cs.CipherSuite, NegotiatedProtocol: cs.NegotiatedProtocol, ServerName: cs.ServerName, PeerCertificates: cs.PeerCertificates, VerifiedChains: cs.VerifiedChains})
		}
	}
	var u *utls.UConn
	if len(cfg.NextProtos) > 0 {
		spec, e := utls.UTLSIdToSpec(id)
		if e != nil {
			return nil, e
		}
		for _, ext := range spec.Extensions {
			if a, ok := ext.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = append([]string(nil), cfg.NextProtos...)
			}
		}
		u = utls.UClient(raw, uc, utls.HelloCustom)
		if e := u.ApplyPreset(&spec); e != nil {
			return nil, e
		}
	} else {
		u = utls.UClient(raw, uc, id)
	}
	if e := u.HandshakeContext(ctx); e != nil {
		return nil, e
	}
	return u, nil
}
