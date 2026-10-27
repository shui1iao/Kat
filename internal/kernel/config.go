package kernel

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/snell"
	VX "github.com/shui1iao/Kat/internal/vlessx"
	VT "github.com/shui1iao/Kat/internal/vtransport"
	XH "github.com/shui1iao/Kat/internal/xhttp"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

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
func (d Duration) value() time.Duration         { return time.Duration(d) }

type User struct {
	Flow     string `json:"flow,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}
type TLSConfig struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// 0.7.0 (Trojan/AnyTLS inbounds only, all optional): see tls_config.go.
	Certificates  []TLSCertFile `json:"certificates,omitempty"`
	Watch         bool          `json:"watch,omitempty"`
	WatchInterval Duration      `json:"watch_interval,omitempty"`
	ALPN          []string      `json:"alpn,omitempty"`
	MinVersion    string        `json:"min_version,omitempty"`
	MaxVersion    string        `json:"max_version,omitempty"`
	CipherSuites  []string      `json:"cipher_suites,omitempty"`
	ACME          *ACMEConfig   `json:"acme,omitempty"`
}
type Inbound struct {
	logIndex      int
	xhttpServer   *XH.Server
	Transport     *VTransportOptions `json:"transport,omitempty"`
	Reality       *RealityOptions    `json:"reality,omitempty"`
	realityServer *VX.RealityServer
	AnyTLS        *AnyTLSOptions `json:"anytls,omitempty"`
	anytlsAuth    *anyTLSAuthority
	anytlsServer  *A.Server
	Protocol      string        `json:"protocol"`
	Listen        string        `json:"listen"`
	Users         []User        `json:"users,omitempty"`
	TLS           *TLSConfig    `json:"tls,omitempty"`
	AllowInsecure bool          `json:"allow_insecure,omitempty"`
	SS            *SSOptions    `json:"ss,omitempty"`
	Snell         *SnellOptions `json:"snell,omitempty"`
	ssRuntime     *ssRuntime
	snellServer   *snell.Server
	tlsConfig     *tls.Config
	TCPFastOpen   bool       `json:"tcp_fast_open,omitempty"`
	serverTLS     *serverTLS // Trojan/AnyTLS certificate sources (tls_config.go)
	// Codec configurations, compared by a reload to reuse identical codecs.
	xhttpConf  XH.Config
	anytlsConf A.Config
	snellConf  snell.Config
	// tlsWritten: the JSON object had a "tls" member (even null).
	// ephemeralTLS: tlsConfig holds a generated in-memory certificate.
	tlsWritten   bool
	ephemeralTLS bool
	// 0.7.0: source lists (all inbounds), Trojan fallback, SOCKS5 options.
	Sources           *SourceOptions `json:"sources,omitempty"`
	Fallback          string         `json:"fallback,omitempty"`
	SOCKS5            *SOCKS5Options `json:"socks5,omitempty"`
	srcAllow, srcDeny []netip.Prefix
	// anytlsSessionsAuto is the max_sessions value Validate derived from
	// limits.connections for an omitted/0 AnyTLS max_sessions (0 = written
	// explicitly). Like Limits.logicalAuto, re-validation derives it again.
	anytlsSessionsAuto int

	// 0.7.0: optional name (in_name rules) and per-inbound traffic sniffing.
	Name  string        `json:"name,omitempty"`
	Sniff *SniffOptions `json:"sniff,omitempty"`
}
type Limits struct {
	LogicalStreams   int      `json:"logical_streams"`
	Connections      int      `json:"connections"`
	Handshakes       int      `json:"handshakes"`
	Dials            int      `json:"dials"`
	UDPAssociations  int      `json:"udp_associations"`
	UDPQueueBytes    int      `json:"udp_queue_bytes"`
	UDPQueue         int      `json:"udp_queue"`
	UDPTargets       int      `json:"udp_targets"`
	BufferSize       int      `json:"buffer_size"`
	PoolBuffers      int      `json:"pool_buffers"`
	HandshakeTimeout Duration `json:"handshake_timeout"`
	DialTimeout      Duration `json:"dial_timeout"`
	DrainTimeout     Duration `json:"drain_timeout"`
	TCPIdle          Duration `json:"tcp_idle"`
	UDPIdle          Duration `json:"udp_idle"`
	DisableFastPath  bool     `json:"disable_fast_path"`
	UDPFragmentBytes int      `json:"udp_fragment_bytes,omitempty"` // 0.7.0: SOCKS5 UDP reassembly, all associations
	// logicalAuto is the value Validate derived for an omitted/0
	// logical_streams (0 = written explicitly). While LogicalStreams still
	// holds that value, re-validation recomputes it as
	// max(defaultLogicalStreams, sum of AnyTLS identity max_streams).
	logicalAuto int
}

// Defaults sized for several users with Surge/mihomo/sing-box clients that
// open one AnyTLS session (or one TCP connection) per concurrent request.
// All values remain hard bounded and explicit values keep 0.6.1 semantics.
const (
	defaultConnections     = 4096
	defaultLogicalStreams  = 8192
	defaultHandshakes      = 512
	defaultDials           = 512
	defaultUDPAssociations = 1024
	defaultUDPTargets      = 256
	maxResourceCount       = 65536
)

type Config struct {
	DNS         *DNSOptions     `json:"dns,omitempty"`
	Routing     *RoutingOptions `json:"routing,omitempty"`
	UDPBindIPv4 string          `json:"udp_bind_ipv4,omitempty"`
	UDPBindIPv6 string          `json:"udp_bind_ipv6,omitempty"`
	Inbounds    []Inbound       `json:"inbounds"`
	Limits      Limits          `json:"limits"`

	// Routing core (all optional; absent = system DNS + direct as before).
	Providers     []ProviderConfig `json:"providers,omitempty"`
	providerNodes int
	expanded      bool
	raw           []byte
	defaults      [2]string
	stateDir      string           // default ACME storage root, retained for provider rebuilds
	Outbounds     []OutboundConfig `json:"outbounds,omitempty"`
	Groups        []GroupConfig    `json:"groups,omitempty"`
	RuleSets      []RuleSetConfig  `json:"rule_sets,omitempty"`
	GeoIP         *GeoIPConfig     `json:"geoip,omitempty"`
	Geosite       *GeositeConfig   `json:"geosite,omitempty"`
	ASN           *ASNConfig       `json:"asn,omitempty"`
	route         route.Options    // normalized by Validate

	// Runtime (0.7.0, all optional).
	Log      *LogOptions      `json:"log,omitempty"`
	Stats    *StatsOptions    `json:"stats,omitempty"`
	API      *APIOptions      `json:"api,omitempty"`
	Security *SecurityOptions `json:"security,omitempty"`

	// 0.7.0: built-in direct outbound options (optional).
	Direct *DirectOptions `json:"direct,omitempty"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, errors.New("cannot open configuration")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return c, errors.New("configuration exceeds 1 MiB or cannot be read")
	}
	return decodeConfig(b)
}

func decodeConfig(b []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return c, errors.New("invalid configuration JSON or unknown field")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	c.raw = append([]byte(nil), b...)
	return c, c.Validate()
}
func (c *Config) Validate() error {
	if e := c.validateProviders(); e != nil {
		return e
	}
	if e := c.validateNetwork(); e != nil {
		return e
	}
	if e := c.validateOutbounds(); e != nil {
		return e
	}
	if e := c.validateRuntime(); e != nil {
		return e
	}
	for _, b := range []struct {
		value string
		v4    bool
	}{{c.UDPBindIPv4, true}, {c.UDPBindIPv6, false}} {
		if b.value != "" {
			ip := net.ParseIP(b.value)
			if ip == nil || (ip.To4() != nil) != b.v4 {
				return errors.New("invalid UDP bind address family")
			}
		}
	}
	l := &c.Limits
	def := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	logicalAuto := l.LogicalStreams == 0 || (l.logicalAuto != 0 && l.LogicalStreams == l.logicalAuto)
	l.logicalAuto = 0
	if logicalAuto {
		// Raised below to cover all AnyTLS identity worker budgets.
		l.LogicalStreams = defaultLogicalStreams
		l.logicalAuto = l.LogicalStreams
	}
	def(&l.Connections, defaultConnections)
	def(&l.Handshakes, defaultHandshakes)
	def(&l.Dials, defaultDials)
	def(&l.UDPAssociations, defaultUDPAssociations)
	def(&l.UDPQueue, 16)
	def(&l.UDPQueueBytes, l.UDPQueue*maxDatagram)
	def(&l.UDPTargets, defaultUDPTargets)
	def(&l.BufferSize, 16384)
	def(&l.PoolBuffers, 128)
	dd := func(p *Duration, v time.Duration) {
		if *p == 0 {
			*p = Duration(v)
		}
	}
	dd(&l.HandshakeTimeout, 10*time.Second)
	dd(&l.DialTimeout, 5*time.Second)
	dd(&l.DrainTimeout, 5*time.Second)
	dd(&l.UDPIdle, 60*time.Second)

	for _, v := range []int{l.Connections, l.LogicalStreams, l.Handshakes, l.Dials, l.UDPAssociations, l.PoolBuffers} {
		if v < 1 || v > maxResourceCount {
			return errors.New("resource count must be between 1 and 65536")
		}
	}
	if l.UDPQueueBytes < 1 || l.UDPQueueBytes > 256*maxDatagram {
		return errors.New("invalid UDP queue byte budget")
	}
	if l.UDPQueue < 1 || l.UDPQueue > 256 || l.UDPTargets < 1 || l.UDPTargets > 1024 || l.BufferSize < 1024 || l.BufferSize > 65536 {
		return errors.New("invalid queue, target or buffer limit")
	}
	for _, v := range []Duration{l.HandshakeTimeout, l.DialTimeout, l.DrainTimeout, l.UDPIdle} {
		if v.value() < time.Millisecond || v.value() > 24*time.Hour {
			return errors.New("timeouts must be between 1ms and 24h")
		}
	}
	if l.TCPIdle < 0 || l.TCPIdle.value() > 24*time.Hour {
		return errors.New("invalid TCP idle timeout (0 disables for non-Snell)")
	}
	if len(c.Inbounds) == 0 || len(c.Inbounds) > 64 {
		return errors.New("need 1..64 inbounds")
	}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		host, _, e := net.SplitHostPort(in.Listen)
		if e != nil {
			return fmt.Errorf("inbound %d: invalid listen address", i)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("inbound %d: listen host must be a literal IP", i)
		}
		a, e := net.ResolveTCPAddr("tcp", in.Listen)
		if e != nil || a.Port < 0 {
			return fmt.Errorf("inbound %d: invalid listen port", i)
		}
		if len(in.Users) > 1024 {
			return errors.New("too many users")
		}
		if in.Protocol != "shadowsocks" && in.SS != nil || in.Protocol != "snell" && in.Snell != nil {
			return errors.New("protocol options do not match inbound")
		}
		if in.Protocol != "anytls" && in.AnyTLS != nil {
			return errors.New("AnyTLS options do not match protocol")
		}
		if in.Protocol != "vless" && (in.Transport != nil || in.Reality != nil) {
			return errors.New("VLESS-only transport/security options")
		}
		for _, u := range in.Users {
			if in.Protocol != "vless" && u.Flow != "" {
				return errors.New("flow only valid for VLESS")
			}
		}
		switch in.Protocol {
		case "anytls":
			// Omitted "tls" = ephemeral certificate; a written but null "tls" stays an error.
			if (in.TLS == nil && in.tlsWritten) || len(in.Users) != 0 {
				return errors.New("AnyTLS requires TLS and single password options")
			}
			// An omitted max_sessions follows limits.connections. While the
			// options still hold the derived value, re-validation (as Start
			// does) derives it again from the current connections.
			if o := in.AnyTLS; o != nil && in.anytlsSessionsAuto != 0 && o.MaxSessions == in.anytlsSessionsAuto {
				o.MaxSessions = 0
			}
			sessionsAuto := in.AnyTLS != nil && in.AnyTLS.MaxSessions == 0
			in.anytlsSessionsAuto = 0
			if e := in.AnyTLS.normalize(l.Connections); e != nil {
				return e
			}
			if sessionsAuto {
				in.anytlsSessionsAuto = in.AnyTLS.MaxSessions
			}
		case "shadowsocks":
			if in.TLS != nil || len(in.Users) != 0 {
				return errors.New("SS uses its own encrypted transport and single identity")
			}
			if in.SS == nil {
				return errors.New("SS options required")
			}
			if e := in.SS.validate(); e != nil {
				return e
			}
		case "snell":
			if in.TLS != nil || len(in.Users) != 0 {
				return errors.New("Snell uses one PSK and native obfuscation only")
			}
			if e := in.Snell.validate(); e != nil {
				return e
			}
		case "socks5":
			if len(in.Users) == 0 && !ip.IsLoopback() {
				return errors.New("non-loopback SOCKS5 requires users")
			}
			if in.TLS != nil {
				return errors.New("SOCKS5 TLS wrapper is not implemented")
			}
			seen := map[string]bool{}
			for _, u := range in.Users {
				if len(u.Username) < 1 || len(u.Username) > 255 || len(u.Password) < 1 || len(u.Password) > 255 || u.UUID != "" || seen[u.Username] {
					return errors.New("invalid or duplicate SOCKS5 user")
				}
				seen[u.Username] = true
			}
		case "trojan":
			if in.TLS == nil || len(in.Users) == 0 {
				return errors.New("Trojan requires TLS and password users")
			}
			seen := map[string]bool{}
			for _, u := range in.Users {
				if u.Password == "" || len(u.Password) > 4096 || u.Username != "" || u.UUID != "" || seen[u.Password] {
					return errors.New("invalid or duplicate Trojan credential")
				}
				seen[u.Password] = true
			}
		case "vless":
			if len(in.Users) == 0 {
				return errors.New("VLESS requires UUID users")
			}
			if in.TLS == nil && in.Reality == nil && !ip.IsLoopback() && !in.AllowInsecure {
				return errors.New("non-loopback plaintext VLESS requires explicit allow_insecure")
			}
			if in.TLS != nil && in.Reality != nil {
				return errors.New("TLS and REALITY are mutually exclusive")
			}
			if in.Reality != nil {
				if _, e := in.Reality.config(*l); e != nil {
					return e
				}
			}
			if in.Transport != nil {
				if (in.Transport.Type == "grpc" || in.Transport.Type == "xhttp") && in.TLS == nil {
					return errors.New("gRPC requires actual TLS/h2; h2c unsupported")
				}
				if in.Reality != nil {
					return errors.New("REALITY only supports RAW in this core")
				}
				if in.Transport.MaxStreams == 0 {
					in.Transport.MaxStreams = 16
				}
				if in.Transport.MaxStreams < 1 || in.Transport.MaxStreams > l.LogicalStreams {
					return errors.New("invalid transport stream quota")
				}
				if in.Transport.Type == "xhttp" {
					if in.Transport.MaxEarlyData != 0 || in.Transport.ServiceName != "" {
						return errors.New("XHTTP only default placement; no WS ED/grpc service")
					}
					if in.Transport.XHTTP == nil {
						in.Transport.XHTTP = &XHTTPOptions{}
					}
					if e := in.Transport.XHTTP.validate(in.Transport, *l); e != nil {
						return e
					}
				} else if in.Transport.XHTTP != nil {
					return errors.New("XHTTP options require xhttp type")
				} else if _, e := VT.NewServer(in.Transport.config(*l)); e != nil {
					return errors.New("invalid VLESS transport endpoint")
				}
			}
			seen := map[[16]byte]bool{}
			for _, u := range in.Users {
				if u.Flow != "" && u.Flow != VX.VisionFlow {
					return errors.New("unsupported VLESS flow")
				}
				if u.Flow != "" && (in.Transport != nil || (in.TLS == nil && in.Reality == nil)) {
					return errors.New("Vision requires RAW TLS1.3 or local REALITY")
				}
				v, e := parseUUID(u.UUID)
				if e != nil || u.Password != "" || u.Username != "" || seen[v] {
					return errors.New("invalid or duplicate VLESS UUID")
				}
				seen[v] = true
			}
		default:
			return errors.New("unsupported inbound protocol")
		}
		if in.TLS != nil && (in.Protocol == "trojan" || in.Protocol == "anytls") {
			if e := in.validateServerTLS(); e != nil {
				return e
			}
		} else if in.TLS != nil {
			if in.TLS.extended() {
				return errors.New("extended TLS options apply to Trojan and AnyTLS inbounds only")
			}
			cert, e := tls.LoadX509KeyPair(in.TLS.Cert, in.TLS.Key)
			if e != nil {
				return errors.New("cannot load TLS certificate/key")
			}
			in.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			in.ephemeralTLS = false
			if in.Protocol == "vless" {
				for _, u := range in.Users {
					if u.Flow == VX.VisionFlow {
						in.tlsConfig.MinVersion = tls.VersionTLS13
					}
				}
				if in.Transport != nil {
					if in.Transport.Type == "xhttp" {
						in.tlsConfig.NextProtos = []string{"h2", "http/1.1"}
						if len(in.Transport.XHTTP.ALPN) > 0 {
							in.tlsConfig.NextProtos = append([]string(nil), in.Transport.XHTTP.ALPN...)
						}
					} else if in.Transport.Type == "grpc" {
						in.tlsConfig.NextProtos = []string{"h2"}
					} else {
						in.tlsConfig.NextProtos = []string{"http/1.1"}
					}
				}
			}
		} else if in.Protocol == "anytls" && !in.ephemeralTLS {
			// One certificate per loaded configuration: Start re-validating
			// the same Config keeps it; every new Load generates a new one.
			cfg, e := ephemeralTLSConfig(time.Now())
			if e != nil {
				return errors.New("cannot generate TLS certificate")
			}
			in.tlsConfig, in.ephemeralTLS = cfg, true
		}
	}
	if e := c.validateSecurity(); e != nil {
		return e
	}
	seenAny := map[string]AnyTLSOptions{}
	seenSS := map[string]SSOptions{}
	seenSn := map[string]SnellOptions{}
	for _, in := range c.Inbounds {
		if in.AnyTLS != nil {
			if old, ok := seenAny[in.AnyTLS.Password]; ok && old != *in.AnyTLS {
				return errors.New("same AnyTLS identity has conflicting limits or padding scheme")
			}
			seenAny[in.AnyTLS.Password] = *in.AnyTLS
		}
		if in.SS != nil {
			id, _ := in.SS.identity()
			if prev, ok := seenSS[id]; ok && prev.protection() != in.SS.protection() {
				return errors.New("same SS identity has conflicting settings")
			}
			seenSS[id] = *in.SS
		}
		if in.Snell != nil {
			if prev, ok := seenSn[in.Snell.PSK]; ok && (prev.Obfs != in.Snell.Obfs || prev.ReplayCapacity != in.Snell.ReplayCapacity || prev.MaxRequests != in.Snell.MaxRequests) {
				return errors.New("same Snell PSK requires same obfs/protection settings")
			}
			seenSn[in.Snell.PSK] = *in.Snell
		}
	}
	totalAnyWorkers := 0
	for _, o := range seenAny {
		totalAnyWorkers += o.MaxStreams
	}
	if logicalAuto && totalAnyWorkers > l.LogicalStreams {
		if totalAnyWorkers > maxResourceCount {
			return errors.New("AnyTLS identity worker budgets exceed the 65536 logical_streams maximum; set explicit max_streams per identity")
		}
		l.LogicalStreams = totalAnyWorkers
		l.logicalAuto = l.LogicalStreams
	}
	if totalAnyWorkers > l.LogicalStreams {
		return errors.New("AnyTLS identity worker budgets exceed logical_streams; allocate explicit bounded identity quotas")
	}
	return nil
}
func parseUUID(s string) (v [16]byte, e error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return v, errors.New("UUID must be canonical")
	}
	b, e := hex.DecodeString(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:])
	if e != nil {
		return v, errors.New("invalid UUID")
	}
	copy(v[:], b)
	return v, nil
}
