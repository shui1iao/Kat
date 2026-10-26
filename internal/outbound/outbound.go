// Package outbound is Kat's shared outbound contract. It is used by the server
// kernel today and is intended to be embedded unchanged by a future client.
// Everything here must stay pure Go and portable (linux/windows/darwin).
//
// STABLE CONTRACT: protocol, group, route and kernel packages are all built
// against these types. Changing an exported signature here affects every one
// of them and must be reviewed together.
package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Addr is a destination. Host is either a canonical IP literal (no zone) or a
// lowercase DNS name; domain names are forwarded to proxies unresolved.
type Addr struct {
	Host string
	Port uint16
}

func (a Addr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }

// IP returns the literal address when Host is an IP literal.
func (a Addr) IP() (netip.Addr, bool) {
	ip, e := netip.ParseAddr(a.Host)
	if e != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

var (
	// ErrUDPUnsupported: this outbound (or a hop of its chain) cannot carry UDP.
	ErrUDPUnsupported = errors.New("outbound: UDP not supported")
	// ErrRejected: the built-in reject outbound, or a group whose only usable choice is reject.
	ErrRejected = errors.New("outbound: rejected")
	// ErrNoMember: a group currently has no usable member for this network.
	ErrNoMember = errors.New("outbound: no usable group member")
)

// PacketConn is a destination-addressed datagram channel. Each ReadFrom returns
// exactly one whole datagram and the address it came from (as reported by the
// last hop). Close unblocks pending reads/writes. Implementations must be safe
// for one concurrent reader plus one concurrent writer.
type PacketConn interface {
	WriteTo(p []byte, dst Addr) (int, error)
	ReadFrom(p []byte) (n int, src Addr, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Dialer is what an outbound needs from the hop beneath it (direct or another
// outbound/group). UDP() is the static capability of this hop INCLUDING its own
// underlying chain; ListenPacket returns ErrUDPUnsupported when it is false.
type Dialer interface {
	DialTCP(ctx context.Context, dst Addr) (net.Conn, error)
	ListenPacket(ctx context.Context) (PacketConn, error)
	UDP() bool
}

// Outbound is a named Dialer. Close releases background resources (session
// pools, probe loops); in-flight connections are owned by their callers.
type Outbound interface {
	Dialer
	Name() string
	Type() string
	Close() error
}

// EventSink receives rare, bounded operational events. fields are key,value
// pairs of NON-SENSITIVE strings only (names, counts, classes) — never
// credentials, payload, destination or client addresses. May be nil.
type EventSink func(event string, fields ...string)

func (s EventSink) Emit(event string, fields ...string) {
	if s != nil {
		s(event, fields...)
	}
}

type sourceKey struct{}

// WithSource attaches the client source address to ctx (used by groups that
// balance per source, e.g. load-balance sticky-sessions). Never logged.
func WithSource(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, sourceKey{}, ip)
}

// SourceFrom returns the client source address attached by WithSource
// (invalid when none).
func SourceFrom(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(sourceKey{}).(netip.Addr)
	return ip
}

// Duration is a JSON string duration ("5s", "10m").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("duration must be a string")
	}
	v, e := time.ParseDuration(s)
	if e != nil {
		return errors.New("invalid duration")
	}
	*d = Duration(v)
	return nil
}
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }
func (d Duration) Value() time.Duration         { return time.Duration(d) }

// Options is one entry of the root "outbounds" array. Field applicability is
// per Type and validated strictly by the owning protocol package:
//
//	socks5:      server, port, [username, password], [udp], [via]
//	shadowsocks: server, port, method, password (2017) | key (2022, base64), [udp], [via]
//	trojan:      server, port, password, tls, [udp], [via]
//	anytls:      server, port, password, tls, [udp], [via], [idle_sessions], [idle_timeout]
//
// UDP defaults to enabled when the protocol (and chain) can carry it; an
// explicit false disables UDP for this outbound.
type Options struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Server       string      `json:"server"`
	Port         uint16      `json:"port"`
	Via          string      `json:"via,omitempty"`
	UDP          *bool       `json:"udp,omitempty"`
	Username     string      `json:"username,omitempty"`
	Password     string      `json:"password,omitempty"`
	Method       string      `json:"method,omitempty"`
	Key          string      `json:"key,omitempty"`
	TLS          *TLSOptions `json:"tls,omitempty"`
	IdleSessions int         `json:"idle_sessions,omitempty"`
	IdleTimeout  Duration    `json:"idle_timeout,omitempty"`
}

// UDPEnabled reports the configured UDP switch (default true).
func (o Options) UDPEnabled() bool { return o.UDP == nil || *o.UDP }

// ServerAddr returns the proxy server address (host normalized to lowercase).
func (o Options) ServerAddr() Addr { return Addr{strings.ToLower(o.Server), o.Port} }

// TLSOptions configures client TLS for trojan/anytls outbounds.
//
// Verification modes (exactly one applies):
//   - default: standard chain + hostname verification against system roots,
//     or against the PEM bundle in CA when set;
//   - pin_sha256: accept iff the leaf certificate DER SHA-256 (64 hex chars,
//     optional ':' separators, case-insensitive) matches; chain/hostname are
//     not checked (supports self-signed servers safely);
//   - insecure: true: no verification at all (explicit user opt-in only).
//
// pin_sha256 and insecure are mutually exclusive; ca with insecure is rejected.
type TLSOptions struct {
	ServerName string   `json:"server_name,omitempty"`
	CA         string   `json:"ca,omitempty"`
	PinSHA256  string   `json:"pin_sha256,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	// Fingerprint (0.7.0) makes the ClientHello imitate a browser through
	// uTLS: chrome, firefox, safari, ios, edge, android, 360, qq, random
	// (one of chrome/firefox/safari/ios/edge, chosen once per process).
	// Empty = Go crypto/tls.
	Fingerprint string `json:"fingerprint,omitempty"`
}

var errTLSOptions = errors.New("invalid outbound TLS options")

// ClientConfig builds the tls.Config. defaultServerName is the outbound server
// host (used for SNI/verification when server_name is empty; IP literals get
// no SNI but are still verified against IP SANs in default mode).
func (o *TLSOptions) ClientConfig(defaultServerName string) (*tls.Config, error) {
	if o == nil {
		o = &TLSOptions{}
	}
	if o.Insecure && (o.PinSHA256 != "" || o.CA != "") {
		return nil, errTLSOptions
	}
	if len(o.ALPN) > 8 {
		return nil, errTLSOptions
	}
	for _, p := range o.ALPN {
		if p == "" || len(p) > 255 {
			return nil, errTLSOptions
		}
	}
	name := o.ServerName
	if name == "" {
		name = defaultServerName
	}
	c := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, NextProtos: append([]string(nil), o.ALPN...)}
	if o.CA != "" {
		pem, e := os.ReadFile(o.CA)
		if e != nil || len(pem) > 1<<20 {
			return nil, errTLSOptions
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errTLSOptions
		}
		c.RootCAs = pool
	}
	switch {
	case o.Insecure:
		c.InsecureSkipVerify = true
	case o.PinSHA256 != "":
		want, e := hex.DecodeString(strings.ReplaceAll(strings.ToLower(o.PinSHA256), ":", ""))
		if e != nil || len(want) != sha256.Size {
			return nil, errTLSOptions
		}
		// Pinning replaces chain/hostname verification; the pin itself is checked
		// on every handshake (including resumption, which crypto/tls re-verifies
		// through VerifyConnection).
		c.InsecureSkipVerify = true
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls: no peer certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("tls: certificate pin mismatch")
			}
			return nil
		}
	}
	return c, nil
}
