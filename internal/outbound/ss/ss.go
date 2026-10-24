// Package ss is a Shadowsocks client outbound: AEAD-2017 (aes-128-gcm,
// aes-256-gcm, chacha20-ietf-poly1305; password) and SIP022 (2022-blake3-*;
// single base64 PSK, no EIH). TCP and native UDP; every connection or
// datagram to the server goes through the "under" dialer.
package ss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // EVP_BytesToKey for AEAD-2017 password compatibility only.
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"

	"github.com/shui1iao/Kat/internal/outbound"
)

const typeName = "shadowsocks"

var errOptions = errors.New("shadowsocks: invalid outbound options")

type method struct {
	name          string
	keySize       int
	v2022, chacha bool
}

func lookup(name string) (method, bool) {
	m := method{name: name}
	switch name {
	case "aes-128-gcm":
		m.keySize = 16
	case "aes-256-gcm":
		m.keySize = 32
	case "chacha20-ietf-poly1305":
		m.keySize, m.chacha = 32, true
	case "2022-blake3-aes-128-gcm":
		m.keySize, m.v2022 = 16, true
	case "2022-blake3-aes-256-gcm":
		m.keySize, m.v2022 = 32, true
	case "2022-blake3-chacha20-poly1305":
		m.keySize, m.v2022, m.chacha = 32, true, true
	default:
		return m, false
	}
	return m, true
}

// Validate checks o statically (no I/O).
func Validate(o outbound.Options) error {
	_, _, e := parse(o)
	return e
}

func parse(o outbound.Options) (method, []byte, error) {
	var m method
	if o.Type != typeName {
		return m, nil, fmt.Errorf("%w: type must be %q", errOptions, typeName)
	}
	if o.Name == "" {
		return m, nil, fmt.Errorf("%w: name required", errOptions)
	}
	if !validServer(o.Server) {
		return m, nil, fmt.Errorf("%w: server must be an IP literal or a valid domain name", errOptions)
	}
	if o.Port == 0 {
		return m, nil, fmt.Errorf("%w: port must be 1..65535", errOptions)
	}
	if o.Username != "" || o.TLS != nil || o.IdleSessions != 0 || o.IdleTimeout != 0 {
		return m, nil, fmt.Errorf("%w: only server, port, method, password|key, udp, via apply to shadowsocks", errOptions)
	}
	m, ok := lookup(o.Method)
	if !ok {
		return m, nil, fmt.Errorf("%w: unsupported method", errOptions)
	}
	if m.v2022 {
		if o.Password != "" {
			return m, nil, fmt.Errorf("%w: %s uses key (base64 PSK), not password", errOptions, m.name)
		}
		if strings.Contains(o.Key, ":") {
			return m, nil, fmt.Errorf("%w: multi-user EIH keys are not supported", errOptions)
		}
		k, e := base64.StdEncoding.Strict().DecodeString(o.Key)
		if e != nil || len(k) != m.keySize {
			return m, nil, fmt.Errorf("%w: key must be standard base64 of %d bytes", errOptions, m.keySize)
		}
		return m, k, nil
	}
	if o.Key != "" {
		return m, nil, fmt.Errorf("%w: %s uses password, not key", errOptions, m.name)
	}
	if o.Password == "" || len(o.Password) > 4096 {
		return m, nil, fmt.Errorf("%w: password must be 1..4096 bytes", errOptions)
	}
	return m, evpBytesToKey(o.Password, m.keySize), nil
}

func evpBytesToKey(password string, size int) []byte {
	key := make([]byte, 0, size+md5.Size)
	var prev []byte
	for len(key) < size {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:size]
}

// sessionAEAD derives the per-salt (2017/2022 TCP, 2017 UDP) or per-session-ID
// (2022 UDP AES variants) AEAD.
func sessionAEAD(m method, key, salt []byte) (cipher.AEAD, error) {
	sub := make([]byte, m.keySize)
	if m.v2022 {
		material := make([]byte, 0, len(key)+len(salt))
		material = append(append(material, key...), salt...)
		blake3.DeriveKey(sub, "shadowsocks 2022 session subkey", material)
	} else if _, e := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), sub); e != nil {
		return nil, e
	}
	if m.chacha {
		return chacha20poly1305.New(sub)
	}
	b, e := aes.NewCipher(sub)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}

// checkTime enforces the SIP022 30-second timestamp window.
func checkTime(stamp uint64, now time.Time) bool {
	n := now.Unix()
	if n < 0 {
		return false
	}
	u := uint64(n)
	if stamp > u {
		return stamp-u <= 30
	}
	return u-stamp <= 30
}

// validServer accepts an IP literal without zone or an LDH domain name.
func validServer(s string) bool {
	if s == "" {
		return false
	}
	if ip, e := netip.ParseAddr(s); e == nil {
		return ip.Zone() == ""
	}
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
