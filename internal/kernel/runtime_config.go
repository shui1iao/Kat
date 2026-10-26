package kernel

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// LogOptions is the optional root "log" block. Omitted = 0.6.3 behaviour:
// level info, text lines on stderr, no access log.
type LogOptions struct {
	Level      string `json:"level,omitempty"`       // debug | info (default) | warn | error
	Format     string `json:"format,omitempty"`      // text (default) | json
	File       string `json:"file,omitempty"`        // empty = stderr (journald under systemd)
	MaxSizeMB  int    `json:"max_size_mb,omitempty"` // rotate the file at this size, default 10
	MaxBackups int    `json:"max_backups,omitempty"` // rotated files kept, default 3
	Access     bool   `json:"access,omitempty"`      // one line per proxied connection, default off
}

// StatsOptions is the optional root "stats" block. Traffic statistics are
// always kept in memory; this block controls persistence and the optional
// per-connection details.
type StatsOptions struct {
	File         string   `json:"file,omitempty"`          // persistence file; empty = the CLI default path
	Persist      *bool    `json:"persist,omitempty"`       // default true
	SaveInterval Duration `json:"save_interval,omitempty"` // default 60s, 5s..24h
	Connections  bool     `json:"connections,omitempty"`   // active connection details in memory, default off
}

// APIOptions is the optional root "api" block (management interface).
type APIOptions struct {
	Enabled *bool  `json:"enabled,omitempty"` // default true (Unix socket)
	Socket  string `json:"socket,omitempty"`  // empty = the CLI default path
	Listen  string `json:"listen,omitempty"`  // optional loopback TCP listener, e.g. 127.0.0.1:9090
	Secret  string `json:"secret,omitempty"`  // required with listen: Bearer token, >= 16 bytes
}

// SecurityOptions is the optional root "security" block. allow_loopback and
// block_private apply to the final direct dial of proxied client traffic
// (TCP and UDP); auth_ban and max_connections_per_ip to accepted inbound
// connections.
type SecurityOptions struct {
	AllowLoopback bool `json:"allow_loopback,omitempty"` // default false: loopback/unspecified destinations refused
	BlockPrivate  bool `json:"block_private,omitempty"`  // default false: private/link-local destinations allowed

	// 0.7.0 inbound protection (security_inbound.go), both off by default.
	AuthBan             *AuthBanOptions `json:"auth_ban,omitempty"`
	MaxConnectionsPerIP int             `json:"max_connections_per_ip,omitempty"`
}

const (
	defaultLogMaxSizeMB  = 10
	defaultLogMaxBackups = 3
	defaultSaveInterval  = 60 * time.Second
	minAPISecret         = 16
)

func (c *Config) validateRuntime() error {
	if l := c.Log; l != nil {
		if _, ok := parseLevel(l.Level); !ok {
			return errors.New("log.level must be debug, info, warn or error")
		}
		switch l.Format {
		case "", "text", "json":
		default:
			return errors.New("log.format must be text or json")
		}
		if l.MaxSizeMB == 0 {
			l.MaxSizeMB = defaultLogMaxSizeMB
		}
		if l.MaxBackups == 0 {
			l.MaxBackups = defaultLogMaxBackups
		}
		if l.MaxSizeMB < 1 || l.MaxSizeMB > 1024 || l.MaxBackups < 0 || l.MaxBackups > 100 {
			return errors.New("log.max_size_mb must be 1..1024 and log.max_backups 0..100")
		}
		if l.File != "" && !filepath.IsAbs(l.File) {
			return errors.New("log.file must be an absolute path")
		}
	}
	if s := c.Stats; s != nil {
		if s.SaveInterval == 0 {
			s.SaveInterval = Duration(defaultSaveInterval)
		}
		if s.SaveInterval.value() < 5*time.Second || s.SaveInterval.value() > 24*time.Hour {
			return errors.New("stats.save_interval must be between 5s and 24h")
		}
		if s.File != "" && !filepath.IsAbs(s.File) {
			return errors.New("stats.file must be an absolute path")
		}
	}
	if a := c.API; a != nil {
		if a.Socket != "" && !filepath.IsAbs(a.Socket) {
			return errors.New("api.socket must be an absolute path")
		}
		if a.Listen != "" {
			ap, e := netip.ParseAddrPort(a.Listen)
			if e != nil || ap.Port() == 0 {
				return errors.New("api.listen must be a literal loopback IP and non-zero port")
			}
			if ip := ap.Addr(); ip.Zone() != "" || !ip.Unmap().IsLoopback() {
				return errors.New("api.listen must be a loopback address (127.0.0.0/8 or ::1)")
			}
			if len(a.Secret) < minAPISecret || strings.TrimSpace(a.Secret) != a.Secret {
				return errors.New("api.listen requires api.secret of at least 16 bytes without surrounding spaces")
			}
		} else if a.Secret != "" {
			return errors.New("api.secret is only used with api.listen")
		}
	}
	return nil
}

// apiEnabled reports whether the management API should run at all.
func (c *Config) apiEnabled() bool {
	return c.API != nil && (c.API.Enabled == nil || *c.API.Enabled) && (c.API.Socket != "" || c.API.Listen != "")
}

// persistStats reports whether statistics are loaded from and saved to a file.
func (c *Config) persistStats() bool {
	return c.Stats != nil && c.Stats.File != "" && (c.Stats.Persist == nil || *c.Stats.Persist)
}

// statsSaveInterval returns the validated save interval (default 60s).
func (c *Config) statsSaveInterval() time.Duration {
	if c.Stats == nil || c.Stats.SaveInterval == 0 {
		return defaultSaveInterval
	}
	return c.Stats.SaveInterval.value()
}

// connectionDetails reports whether active connection details are kept.
func (c *Config) connectionDetails() bool { return c.Stats != nil && c.Stats.Connections }

// accessLog reports whether one access line is written per proxied connection.
func (c *Config) accessLog() bool { return c.Log != nil && c.Log.Access }

// ApplyDefaultPaths fills the management socket and statistics file with the
// given per-instance defaults when they are not configured. Only the CLI "run"
// command calls it; servers started directly (tests, embedding) create no
// files unless configured explicitly.
func (c *Config) ApplyDefaultPaths(socket, statsFile string) {
	c.defaults = [2]string{socket, statsFile}
	if c.API == nil {
		c.API = &APIOptions{}
	}
	if c.API.Socket == "" && (c.API.Enabled == nil || *c.API.Enabled) {
		c.API.Socket = socket
	}
	if c.Stats == nil {
		c.Stats = &StatsOptions{}
	}
	if c.Stats.File == "" {
		c.Stats.File = statsFile
	}
	if c.Stats.SaveInterval == 0 {
		c.Stats.SaveInterval = Duration(defaultSaveInterval)
	}
}

// APISocket returns the configured management socket path ("" = none).
func (c *Config) APISocket() string {
	if c.API == nil || (c.API.Enabled != nil && !*c.API.Enabled) {
		return ""
	}
	return c.API.Socket
}

// destination guard ---------------------------------------------------------

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// localDestination: loopback (127.0.0.0/8, ::1), unspecified addresses that
// reach this host (0.0.0.0/8, ::), in any IPv4-mapped form.
func localDestination(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	return ip.Is4() && ip.As4()[0] == 0
}

func privateDestination(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// blockedDestination applies the security options to one resolved address.
func (c *Config) blockedDestination(ip netip.Addr) bool {
	sec := SecurityOptions{}
	if c.Security != nil {
		sec = *c.Security
	}
	if !sec.AllowLoopback && localDestination(ip) {
		return true
	}
	return sec.BlockPrivate && privateDestination(ip)
}
