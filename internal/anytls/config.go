// Package anytls implements an independently written AnyTLS v2/v1 server
// session codec. The caller supplies an already handshaken, secure TLS transport.
package anytls

import (
	"crypto/md5" // Wire padding-scheme fingerprint, not password security.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MagicUDPHost = "sp.v2.udp-over-tcp.arpa"
const DefaultPaddingScheme = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
const (
	cmdWaste byte = iota
	cmdSYN
	cmdPSH
	cmdFIN
	cmdSettings
	cmdAlert
	cmdPadding
	cmdSYNACK
	cmdHeartRequest
	cmdHeartResponse
	cmdServerSettings
)

var (
	ErrConfig               = errors.New("anytls: invalid configuration")
	ErrAuthentication       = errors.New("anytls: authentication failed")
	ErrProtocol             = errors.New("anytls: protocol violation")
	ErrSessionLimit         = errors.New("anytls: session limit")
	ErrStreamLimit          = errors.New("anytls: stream/worker limit")
	ErrQueueLimit           = errors.New("anytls: frame exceeds queue budget")
	ErrSlowConsumer         = errors.New("anytls: slow consumer blocked session")
	ErrWriteTimeout         = errors.New("anytls: session write timeout")
	ErrStreamClosed         = errors.New("anytls: stream closed")
	ErrHalfCloseUnsupported = errors.New("anytls: FIN closes the stream; half-close unsupported")
	ErrConnectedAddress     = errors.New("anytls: connected UoT address differs")
)

// Config limits are per session except MaxSessions/MaxTotalStreams. Zero values
// select defaults; negative values reject configuration, never disable limits.
// Password is hashed during NewServer and is not retained in the stored Config.
type Config struct {
	Password                                                                               string
	UserID                                                                                 string
	PaddingScheme                                                                          string
	MaxSessions, MaxTotalStreams, MaxStreams                                               int
	MaxSettings, MaxAuthPadding, MaxFrameData, MaxClosedStreams                            int
	StreamInboundFrames, StreamInboundBytes, SessionInboundFrames, SessionInboundBytes     int
	StreamOutboundFrames, StreamOutboundBytes, SessionOutboundFrames, SessionOutboundBytes int
	HandshakeTimeout, TargetTimeout, SlowConsumerTimeout, WriteTimeout                     time.Duration
}
type Server struct {
	cfg               Config
	digest            [32]byte
	paddingMD5        string
	mu                sync.Mutex
	sessions, streams int
}
type ServerStats struct{ Sessions, Streams int }

func (s *Server) Stats() ServerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ServerStats{s.sessions, s.streams}
}
func NewServer(c Config) (*Server, error) {
	if c.Password == "" {
		return nil, fmt.Errorf("%w: empty password", ErrConfig)
	}
	fields := []struct {
		p *int
		d int
	}{
		{&c.MaxSessions, 128}, {&c.MaxTotalStreams, 1024}, {&c.MaxStreams, 64}, {&c.MaxSettings, 4096}, {&c.MaxAuthPadding, 65535}, {&c.MaxFrameData, 65535}, {&c.MaxClosedStreams, 1024},
		{&c.StreamInboundFrames, 16}, {&c.StreamInboundBytes, 131072}, {&c.SessionInboundFrames, 128}, {&c.SessionInboundBytes, 1048576},
		{&c.StreamOutboundFrames, 8}, {&c.StreamOutboundBytes, 131072}, {&c.SessionOutboundFrames, 128}, {&c.SessionOutboundBytes, 1048576},
	}
	for _, f := range fields {
		if *f.p < 0 {
			return nil, ErrConfig
		}
		if *f.p == 0 {
			*f.p = f.d
		}
	}
	if c.MaxSettings > 65535 || c.MaxAuthPadding > 65535 || c.MaxFrameData > 65535 {
		return nil, ErrConfig
	}
	durations := []struct {
		p *time.Duration
		d time.Duration
	}{{&c.HandshakeTimeout, 10 * time.Second}, {&c.TargetTimeout, 10 * time.Second}, {&c.SlowConsumerTimeout, 10 * time.Second}, {&c.WriteTimeout, 10 * time.Second}}
	for _, f := range durations {
		if *f.p < 0 {
			return nil, ErrConfig
		}
		if *f.p == 0 {
			*f.p = f.d
		}
	}
	if c.PaddingScheme == "" {
		c.PaddingScheme = DefaultPaddingScheme
	}
	if err := validatePadding(c.PaddingScheme, c.MaxSettings); err != nil {
		return nil, err
	}
	fingerprint := md5.Sum([]byte(c.PaddingScheme))
	s := &Server{cfg: c, digest: sha256.Sum256([]byte(c.Password)), paddingMD5: hex.EncodeToString(fingerprint[:])}
	s.cfg.Password = ""
	return s, nil
}
func validatePadding(s string, limit int) error {
	if len(s) > limit || !utf8.ValidString(s) {
		return ErrConfig
	}
	lines := strings.Split(s, "\n")
	seen := make(map[string]bool)
	stop := -1
	if len(lines) > 66 {
		return ErrConfig
	}
	for _, line := range lines {
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 || seen[p[0]] {
			return ErrConfig
		}
		seen[p[0]] = true
		if p[0] == "stop" {
			v, e := strconv.Atoi(p[1])
			if e != nil || v < 1 || v > 64 {
				return ErrConfig
			}
			stop = v
			continue
		}
		index, e := strconv.Atoi(p[0])
		if e != nil || index < 0 || index >= 64 {
			return ErrConfig
		}
		tokens := strings.Split(p[1], ",")
		if len(tokens) > 32 || len(tokens) == 0 || (index == 0 && len(tokens) != 1) {
			return ErrConfig
		}
		for _, token := range tokens {
			if token == "c" && index != 0 {
				continue
			}
			v := strings.Split(token, "-")
			if len(v) != 2 {
				return ErrConfig
			}
			lo, e := strconv.Atoi(v[0])
			if e != nil {
				return ErrConfig
			}
			hi, e := strconv.Atoi(v[1])
			if e != nil || lo < 0 || hi < lo || hi > 65535 {
				return ErrConfig
			}
		}
	}
	if stop < 0 {
		return ErrConfig
	}
	for k := range seen {
		if k != "stop" {
			v, _ := strconv.Atoi(k)
			if v >= stop {
				return ErrConfig
			}
		}
	}
	return nil
}
func parseSettings(b []byte) (int, string, error) {
	if !utf8.Valid(b) {
		return 0, "", ErrProtocol
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 32 {
		return 0, "", ErrProtocol
	}
	values := make(map[string]string, len(lines))
	for _, line := range lines {
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 || p[0] == "" || len(p[0]) > 64 || len(p[1]) > 1024 {
			return 0, "", ErrProtocol
		}
		if _, ok := values[p[0]]; ok {
			return 0, "", ErrProtocol
		}
		values[p[0]] = p[1]
	}
	version, e := strconv.Atoi(values["v"])
	if e != nil || version < 1 || version > 255 {
		return 0, "", ErrProtocol
	}
	// client is informational software metadata, not an authentication identity.
	// The protocol describes a string but specifies no nonempty constraint or
	// omission failure. Empty or absent metadata remains unknown; never invent
	// a client name. Key/UTF-8/length/duplicate checks above still apply.
	fp := values["padding-md5"]
	decoded, e := hex.DecodeString(fp)
	if e != nil || len(decoded) != 16 || strings.ToLower(fp) != fp {
		return 0, "", ErrProtocol
	}
	if version > 2 {
		version = 2
	}
	return version, fp, nil
}
func discard(r io.Reader, n int) error {
	var scratch [1024]byte
	for n > 0 {
		take := min(n, len(scratch))
		if _, e := io.ReadFull(r, scratch[:take]); e != nil {
			if e == io.EOF {
				e = io.ErrUnexpectedEOF
			}
			return e
		}
		n -= take
	}
	return nil
}
