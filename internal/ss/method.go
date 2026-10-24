// Package ss implements single-key Shadowsocks AEAD-2017 and SIP022 server codecs.
// It does not listen, dial destinations, route packets, or select a project license.
package ss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // Required only for the AEAD-2017 password-to-key convention.
	"crypto/rand"
	"crypto/sha1" // Required by SIP004 HKDF-SHA1, not a signature primitive.
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

const (
	AES128GCM            = "aes-128-gcm"
	AES256GCM            = "aes-256-gcm"
	ChaCha20Poly1305     = "chacha20-ietf-poly1305"
	AES128GCM2022        = "2022-blake3-aes-128-gcm"
	AES256GCM2022        = "2022-blake3-aes-256-gcm"
	ChaCha20Poly13052022 = "2022-blake3-chacha20-poly1305"
	MaxChunk2017         = 0x3fff
	MaxChunk2022         = 0xffff
	MaxUDPPacketSize     = 65535
	replayTTL            = 61 * time.Second // >=60s plus one second for timestamp rounding
)

var (
	ErrMethod               = errors.New("ss: unsupported method")
	ErrKey                  = errors.New("ss: invalid key")
	ErrFormat               = errors.New("ss: invalid message")
	ErrAuth                 = errors.New("ss: authentication failed")
	ErrReplay               = errors.New("ss: replay or out-of-window packet")
	ErrCapacity             = errors.New("ss: protection cache full")
	ErrTimestamp            = errors.New("ss: timestamp outside 30-second window")
	ErrNonceExhausted       = errors.New("ss: nonce exhausted")
	ErrSessionExpired       = errors.New("ss: expired or foreign UDP session")
	ErrInitialRead          = errors.New("ss: SIP022 initial salt and fixed header not received in one read")
	ErrHalfCloseUnsupported = errors.New("ss: transport does not support CloseWrite")
)

type method struct {
	name          string
	keySize       int
	v2022, chacha bool
}

func lookup(name string) (method, error) {
	m := method{name: name}
	switch name {
	case AES128GCM:
		m.keySize = 16
	case AES256GCM:
		m.keySize = 32
	case ChaCha20Poly1305:
		m.keySize = 32
		m.chacha = true
	case AES128GCM2022:
		m.keySize = 16
		m.v2022 = true
	case AES256GCM2022:
		m.keySize = 32
		m.v2022 = true
	case ChaCha20Poly13052022:
		m.keySize = 32
		m.v2022 = true
		m.chacha = true
	default:
		return m, ErrMethod
	}
	return m, nil
}

// Config configures exactly one user/key/method. Share one Server between all
// listeners/transports using this key, so replay protection cannot be bypassed.
// Zero capacities select bounded defaults; negative values are rejected.
// EIH/iPSK chains and automatic multi-user key probing are not supported.
type Config struct {
	Method         string
	Key            []byte // Raw master key, copied. Not a password or base64 string.
	UserID         string
	MaxTCPSalts    int // SIP022 incoming salts, default 65536.
	MaxUDPSessions int // SIP022 sessions, default 4096.
	// UDPIdle is the SIP022 session inactivity lifetime, not packet timestamp tolerance.
	// Zero preserves the standalone codec default (61s); live state is retained
	// for at least replayTTL even when an association has a shorter idle.
	UDPIdle      time.Duration
	Max2017Salts int // Incoming TCP/UDP and outgoing salts; default32M, process table budget2GiB.
}

type Server struct {
	m        method
	key      []byte
	user     string
	mu       sync.Mutex
	tcpSalts saltStore
	oldSalts compactSaltStore
	udp      sessionStore
	now      func() time.Time
	random   io.Reader
	// SS2022 UDP only: immutable per-Server objects built once from key.
	// AES header block (separate-header variants) or XChaCha AEAD (chacha).
	udpHeader cipher.Block
	udpX      cipher.AEAD
}

func NewServer(c Config) (*Server, error) {
	m, err := lookup(c.Method)
	if err != nil {
		return nil, err
	}
	if len(c.Key) != m.keySize {
		return nil, fmt.Errorf("%w: %s needs %d raw bytes", ErrKey, c.Method, m.keySize)
	}
	if c.MaxTCPSalts < 0 || c.MaxUDPSessions < 0 || c.Max2017Salts < 0 || c.Max2017Salts > default2017Salts {
		return nil, fmt.Errorf("%w: negative capacity", ErrCapacity)
	}
	if c.MaxTCPSalts == 0 {
		c.MaxTCPSalts = 65536
	}
	if c.MaxUDPSessions == 0 {
		c.MaxUDPSessions = 4096
	}
	if c.Max2017Salts == 0 {
		c.Max2017Salts = default2017Salts
	}
	s := &Server{m: m, key: append([]byte(nil), c.Key...), user: c.UserID, now: time.Now, random: rand.Reader}
	s.tcpSalts.init(c.MaxTCPSalts)
	s.oldSalts.init(c.Max2017Salts)
	s.udp.init(c.MaxUDPSessions)
	if c.UDPIdle < 0 || c.UDPIdle > 24*time.Hour {
		return nil, errors.New("ss: invalid UDP idle")
	}
	if c.UDPIdle > s.udp.idle {
		s.udp.idle = c.UDPIdle
	}
	if m.v2022 {
		if m.chacha {
			if s.udpX, err = chacha20poly1305.NewX(s.key); err != nil {
				return nil, err
			}
		} else if s.udpHeader, err = aes.NewCipher(s.key); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// KeyFromBase64 validates a single standard-base64 SIP022 PSK. Colon-separated
// EIH chains are intentionally rejected. The server API always consumes raw keys.
func KeyFromBase64(name, value string) ([]byte, error) {
	m, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if !m.v2022 {
		return nil, ErrKey
	}
	k, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(k) != m.keySize {
		return nil, ErrKey
	}
	return k, nil
}

// PasswordKey2017 implements the specified EVP_BytesToKey-style MD5 expansion
// for 2017 compatibility. It is never available for 2022; it is not a password
// hardening KDF. New deployments should use high-entropy secrets.
func PasswordKey2017(name, password string) ([]byte, error) {
	m, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if m.v2022 {
		return nil, ErrKey
	}
	key := make([]byte, 0, m.keySize)
	var prev []byte
	for len(key) < m.keySize {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:m.keySize], nil
}

func (s *Server) aead(salt []byte) (cipher.AEAD, error) { return deriveAEAD(s.m, s.key, salt) }
func deriveAEAD(m method, key, salt []byte) (cipher.AEAD, error) {
	sub := make([]byte, m.keySize)
	if m.v2022 {
		material := make([]byte, 0, len(key)+len(salt))
		material = append(material, key...)
		material = append(material, salt...)
		blake3.DeriveKey(sub, "shadowsocks 2022 session subkey", material)
	} else {
		if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), sub); err != nil {
			return nil, err
		}
	}
	if m.chacha {
		return chacha20poly1305.New(sub)
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (s *Server) randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(s.random, b)
	return b, err
}
func checkTime(stamp uint64, now time.Time) error {
	n := now.Unix()
	if n < 0 {
		return ErrTimestamp
	}
	u := uint64(n)
	if stamp > u {
		if stamp-u > 30 {
			return ErrTimestamp
		}
	} else if u-stamp > 30 {
		return ErrTimestamp
	}
	return nil
}

// ProtectionStats reports live entries after lazy expiration. No background
// goroutines exist. Capacity exhaustion never evicts unexpired replay state.
type ProtectionStats struct{ TCPSalts, Salts2017, UDPSessions int }

func (s *Server) Stats() ProtectionStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.tcpSalts.expire(now)
	s.oldSalts.expire(now)
	s.udp.expire(now)
	return ProtectionStats{len(s.tcpSalts.entries), s.oldSalts.count, len(s.udp.entries)}
}
