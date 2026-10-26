package kernel

import (
	"context"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	VX "github.com/shui1iao/Kat/internal/vlessx"
	VT "github.com/shui1iao/Kat/internal/vtransport"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

type VTransportOptions struct {
	XHTTP           *XHTTPOptions `json:"xhttp,omitempty"`
	Type            string        `json:"type"` // ws, httpupgrade, grpc
	Path            string        `json:"path,omitempty"`
	Host            string        `json:"host,omitempty"`
	ServiceName     string        `json:"service_name,omitempty"`
	MaxEarlyData    int           `json:"max_early_data,omitempty"`
	MaxStreams      int           `json:"max_streams,omitempty"`
	MaxMessageBytes int           `json:"max_message_bytes,omitempty"`
}
type RealityOptions struct {
	PrivateKey       string   `json:"private_key"` // RawURL base64 X25519
	ShortIDs         []string `json:"short_ids"`   // exact 16 hex chars
	ServerNames      []string `json:"server_names"`
	Decoy            string   `json:"local_decoy"`
	DecoyCA          string   `json:"decoy_ca"`
	MaxTimeDiff      Duration `json:"max_time_diff,omitempty"`
	MinClientVersion []byte   `json:"min_client_version,omitempty"` // JSON base64, use explicit three-byte encoding
	MaxClientVersion []byte   `json:"max_client_version,omitempty"`
	MaxSessions      int      `json:"max_sessions,omitempty"`
}

func (o *VTransportOptions) config(l Limits) VT.Config {
	return VT.Config{Kind: VT.Kind(o.Type), Path: o.Path, Host: o.Host, ServiceName: o.ServiceName, MaxEarlyData: o.MaxEarlyData, MaxConnections: 1, MaxStreams: o.MaxStreams, MaxMessageBytes: o.MaxMessageBytes, HeaderTimeout: l.HandshakeTimeout.value(), IOTimeout: l.DialTimeout.value(), ShutdownTimeout: l.DrainTimeout.value()}
}
func (o *RealityOptions) config(l Limits) (VX.RealityConfig, error) {
	fail := func() (VX.RealityConfig, error) {
		return VX.RealityConfig{}, errors.New("invalid local REALITY config")
	}
	key, e := base64.RawURLEncoding.Strict().DecodeString(o.PrivateKey)
	if e != nil || len(key) != 32 {
		return fail()
	}
	if _, e = ecdh.X25519().NewPrivateKey(key); e != nil {
		return fail()
	}
	decoy, e := netip.ParseAddrPort(o.Decoy)
	if e != nil || !decoy.Addr().IsLoopback() || decoy.Port() == 0 {
		return fail()
	}
	if len(o.ShortIDs) < 1 || len(o.ShortIDs) > 16 || len(o.ServerNames) < 1 || len(o.ServerNames) > 8 {
		return fail()
	}
	var ids [][8]byte
	seen := map[[8]byte]bool{}
	for _, s := range o.ShortIDs {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 8 {
			return fail()
		}
		var id [8]byte
		copy(id[:], b)
		if seen[id] {
			return fail()
		}
		seen[id] = true
		ids = append(ids, id)
	}
	names := map[string]bool{}
	for _, n := range o.ServerNames {
		if len(n) < 1 || len(n) > 253 || strings.ContainsAny(n, " /:\r\n\x00") || names[n] {
			return fail()
		}
		for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
			if len(label) < 1 || len(label) > 63 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(label) {
				return fail()
			}
		}
		names[n] = true
	}
	for _, v := range [][]byte{o.MinClientVersion, o.MaxClientVersion} {
		if len(v) != 0 && len(v) != 3 {
			return fail()
		}
	}
	if len(o.MinClientVersion) == 3 && len(o.MaxClientVersion) == 3 && strings.Compare(string(o.MinClientVersion), string(o.MaxClientVersion)) > 0 {
		return fail()
	}
	if o.MaxTimeDiff == 0 {
		o.MaxTimeDiff = Duration(time.Minute)
	}
	if o.MaxTimeDiff.value() < time.Second || o.MaxTimeDiff.value() > 10*time.Minute {
		return fail()
	}
	if o.MaxSessions == 0 {
		o.MaxSessions = min(l.Connections, 64)
	}
	if o.MaxSessions < 1 || o.MaxSessions > 4096 {
		return fail()
	}
	ca, e := os.ReadFile(o.DecoyCA)
	if e != nil {
		return fail()
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fail()
	}
	return VX.RealityConfig{PrivateKey: key, ShortIDs: ids, ServerNames: o.ServerNames, Decoy: decoy, DecoyRoots: roots, MinClientVersion: o.MinClientVersion, MaxClientVersion: o.MaxClientVersion, MaxTimeDiff: o.MaxTimeDiff.value(), MaxSessions: o.MaxSessions}, nil
}

// prepareVLESS creates the REALITY servers (with a local decoy preflight).
// An identical REALITY configuration reuses the previous server.
func (s *Server) prepareVLESS(prev *Server) error {
	for i := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[i]
		if in.Reality != nil {
			if prev != nil {
				for _, p := range prev.cfg.Inbounds {
					if p.realityServer != nil && p.Reality != nil && reflect.DeepEqual(*p.Reality, *in.Reality) && prev.cfg.Limits == s.cfg.Limits {
						in.realityServer = p.realityServer
						break
					}
				}
				if in.realityServer != nil {
					continue
				}
			}
			cfg, e := in.Reality.config(s.cfg.Limits)
			if e != nil {
				return e
			}
			ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
			rs, e := VX.NewRealityServer(ctx, cfg)
			cancel()
			if e != nil {
				return errors.New("local REALITY decoy preflight failed")
			}
			in.realityServer = rs
		}
	}
	return nil
}
