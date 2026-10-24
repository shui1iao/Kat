package kernel

import (
	"crypto/sha256"
	"errors"
	"github.com/shui1iao/Kat/internal/snell"
	"github.com/shui1iao/Kat/internal/ss"
	"strings"
)

type SSOptions struct {
	Method    string `json:"method"`
	Password  string `json:"password,omitempty"` // only 2017
	Key       string `json:"key,omitempty"`      // standard base64, only 2022
	TCPSalts  int    `json:"tcp_salts,omitempty"`
	Salts2017 int    `json:"salts_2017,omitempty"`
	Sessions  int    `json:"sessions,omitempty"`
	// Per-listener, SS2017 UDP only: unset/0 = default socket (no change, no
	// charge); 1048576 = require actual 1MiB SO_RCVBUF charged to the 8MiB
	// process extra socket budget. Any other value is rejected.
	UDPRcvBuf2017 int `json:"udp_rcvbuf_2017,omitempty"`
}

// protection is the shared-identity part; the per-listener receive buffer is excluded.
func (o SSOptions) protection() SSOptions {
	o.UDPRcvBuf2017 = 0
	return o
}

type SnellOptions struct {
	Version        int    `json:"version"`
	PSK            string `json:"psk"`
	Obfs           string `json:"obfs,omitempty"`
	MaxRequests    int    `json:"max_requests,omitempty"`
	ReplayCapacity int    `json:"replay_capacity,omitempty"`
}

func (o *SSOptions) key() ([]byte, error) {
	if o == nil {
		return nil, errors.New("SS options required")
	}
	if strings.HasPrefix(o.Method, "2022-") {
		if o.Password != "" || o.Key == "" {
			return nil, errors.New("SS2022 requires base64 key, not password")
		}
		return ss.KeyFromBase64(o.Method, o.Key)
	}
	if o.Key != "" || o.Password == "" || len(o.Password) > 4096 {
		return nil, errors.New("SS2017 requires password only")
	}
	return ss.PasswordKey2017(o.Method, o.Password)
}
func (o *SSOptions) identity() (string, error) {
	key, e := o.key()
	if e != nil {
		return "", errors.New("invalid SS method/key")
	}
	sum := sha256.Sum256(append([]byte(o.Method+"\x00"), key...))
	return string(sum[:]), nil
}
func (o *SSOptions) validate() error {
	if _, e := o.key(); e != nil {
		return errors.New("invalid SS method or credential")
	}
	if o.Salts2017 < 0 || o.Salts2017 > 32*1024*1024 {
		return errors.New("SS2017 protection capacity must be 0(default)..33554432")
	}
	switch o.UDPRcvBuf2017 {
	case 0:
	case ss2017RcvBufActual:
		if strings.HasPrefix(o.Method, "2022-") {
			return errors.New("udp_rcvbuf_2017 is only supported on SS2017 listeners, not SS2022")
		}
		if !ss2017RcvBufSupported {
			return errSSRcvBufUnsupported
		}
	default:
		return errors.New("udp_rcvbuf_2017 must be unset (default) or exactly 1048576")
	}
	for _, v := range []int{o.TCPSalts, o.Sessions} {
		if v < 0 || v > 1<<20 {
			return errors.New("SS protection capacity must be 0(default)..1048576")
		}
	}
	return nil
}
func (o *SnellOptions) validate() error {
	if o == nil {
		return errors.New("Snell options required")
	}
	if o.Version != 4 && o.Version != 5 {
		return errors.New("only Snell v4/v5 conventional supported")
	}
	if o.Obfs == "" {
		o.Obfs = "none"
	}
	if o.Obfs != "none" && o.Obfs != "http" {
		return errors.New("Snell obfs must be none or http")
	}
	if len(o.PSK) < 1 || len(o.PSK) > 4096 {
		return errors.New("invalid Snell PSK")
	}
	if o.MaxRequests == 0 {
		o.MaxRequests = 1024
	}
	if o.ReplayCapacity == 0 {
		o.ReplayCapacity = 4096
	}
	if o.MaxRequests < 1 || o.MaxRequests > 1<<20 || o.ReplayCapacity < 1 || o.ReplayCapacity > 1<<20 {
		return errors.New("invalid Snell resource limit")
	}
	return nil
}
func (s *Server) prepareEncrypted() error {
	ssByID := map[string]*ssRuntime{}
	ssOpts := map[string]SSOptions{}
	snByID := map[[32]byte]*snell.Server{}
	snOpts := map[[32]byte]SnellOptions{}
	for i := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[i]
		if in.Protocol == "shadowsocks" {
			id, _ := in.SS.identity()
			if prev, ok := ssOpts[id]; ok && prev.protection() != in.SS.protection() {
				return errors.New("same SS method/key must use identical protection settings")
			}
			rt := ssByID[id]
			if rt == nil {
				key, _ := in.SS.key()
				codec, e := ss.NewServer(ss.Config{Method: in.SS.Method, Key: key, MaxTCPSalts: in.SS.TCPSalts, Max2017Salts: in.SS.Salts2017, MaxUDPSessions: in.SS.Sessions, UDPIdle: s.cfg.Limits.UDPIdle.value()})
				if e != nil {
					return errors.New("cannot initialize SS protection")
				}
				rt = &ssRuntime{codec: codec, v2022: strings.HasPrefix(in.SS.Method, "2022-"), associations: map[ssAssociationID]*ssNativeAssociation{}}
				ssByID[id] = rt
				ssOpts[id] = *in.SS
			}
			in.ssRuntime = rt
		}
		if in.Protocol == "snell" {
			id := sha256.Sum256([]byte(in.Snell.PSK))
			if prev, ok := snOpts[id]; ok && (prev.Obfs != in.Snell.Obfs || prev.MaxRequests != in.Snell.MaxRequests || prev.ReplayCapacity != in.Snell.ReplayCapacity) {
				return errors.New("same Snell PSK requires identical obfs and protection settings")
			}
			codec := snByID[id]
			if codec == nil {
				var e error
				codec, e = snell.NewServer(snell.Config{PSK: []byte(in.Snell.PSK), Obfs: in.Snell.Obfs, MaxSessions: s.cfg.Limits.Connections, MaxRequests: in.Snell.MaxRequests, ReplayCapacity: in.Snell.ReplayCapacity})
				if e != nil {
					return errors.New("cannot initialize Snell protection")
				}
				snByID[id] = codec
				snOpts[id] = *in.Snell
			}
			in.snellServer = codec
		}
	}
	return nil
}
