package kernel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/tlscert"
)

// ---- 0.7.0 inbound TLS options (Trojan / AnyTLS) ----
//
//	"tls": {
//	  "cert": "...", "key": "...",              default certificate (optional with acme)
//	  "certificates": [{"cert","key"}, ...],    more certificates, chosen by SNI
//	  "watch": true, "watch_interval": "60s",   follow external changes of the files
//	  "alpn": ["h2","http/1.1"],
//	  "min_version": "1.2", "max_version": "1.3",
//	  "cipher_suites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ...],  TLS 1.2 only
//	  "acme": {...}                              certificate obtained and renewed by ACME
//	}

// TLSCertFile is one more certificate of an inbound.
type TLSCertFile struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// ACMEConfig is the "tls.acme" block.
type ACMEConfig struct {
	Domains     []string `json:"domains"`
	Email       string   `json:"email,omitempty"`
	Directory   string   `json:"directory,omitempty"`    // default Let's Encrypt production
	DirectoryCA string   `json:"directory_ca,omitempty"` // PEM roots for the ACME server (private/test CA)
	EAB         *ACMEEAB `json:"eab,omitempty"`
	Challenge   string   `json:"challenge"`             // http-01 | tls-alpn-01 | dns-01
	HTTPListen  string   `json:"http_listen,omitempty"` // http-01 standalone, default ":80"
	Webroot     string   `json:"webroot,omitempty"`     // http-01: write the file below this directory
	DNS         *ACMEDNS `json:"dns,omitempty"`         // dns-01 provider
	KeyType     string   `json:"key_type,omitempty"`    // ecdsa (default) | rsa
	Storage     string   `json:"storage,omitempty"`     // default <state directory>/acme
	eabKey      []byte   // decoded EAB MAC key
	dirCA       *x509.CertPool
	dnsToken    string // token read from api_token or api_token_file
}

// ACMEEAB is external account binding (key_id + base64url MAC key).
type ACMEEAB struct {
	KeyID  string `json:"key_id"`
	MACKey string `json:"mac_key"`
}

// ACMEDNS selects the DNS-01 provider.
type ACMEDNS struct {
	Provider           string   `json:"provider"` // cloudflare
	APIToken           string   `json:"api_token,omitempty"`
	APITokenFile       string   `json:"api_token_file,omitempty"`
	ZoneID             string   `json:"zone_id,omitempty"`
	APIURL             string   `json:"api_url,omitempty"`
	Resolvers          []string `json:"resolvers,omitempty"`
	PropagationTimeout Duration `json:"propagation_timeout,omitempty"`
	TTL                int      `json:"ttl,omitempty"`
}

// DirectOptions is the root "direct" block (built-in direct outbound).
type DirectOptions struct {
	TCPFastOpen bool `json:"tcp_fast_open,omitempty"`
}

const (
	defaultWatchInterval = time.Minute
	defaultACMEDirectory = tlscert.LetsEncrypt
)

// serverTLS is the validated certificate setup of one Trojan/AnyTLS inbound.
type serverTLS struct {
	files []*tlscert.FilePair // [0] is the default when tls.cert is set
	watch time.Duration       // 0: files are only re-read by a reload
	acme  *ACMEConfig
	base  *tls.Config // versions, cipher suites, ALPN (no certificates)
}

// extended reports whether a 0.7.0 option is set.
func (t *TLSConfig) extended() bool {
	return len(t.Certificates) > 0 || t.Watch || t.WatchInterval != 0 || len(t.ALPN) > 0 || t.MinVersion != "" || t.MaxVersion != "" || len(t.CipherSuites) > 0 || t.ACME != nil
}

func parseTLSVersion(s string, def uint16) (uint16, error) {
	switch s {
	case "":
		return def, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, errors.New("tls versions must be \"1.2\" or \"1.3\"")
}

// tls12Suites maps the names of the TLS 1.2 cipher suites Go considers secure.
func tls12Suites() map[string]uint16 {
	m := map[string]uint16{}
	for _, s := range tls.CipherSuites() {
		for _, v := range s.SupportedVersions {
			if v == tls.VersionTLS12 {
				m[s.Name] = s.ID
			}
		}
	}
	return m
}

// validateServerTLS checks and loads the TLS block of a Trojan/AnyTLS inbound
// and builds the static configuration (the running server replaces it with a
// dynamic one, see tls_runtime.go).
func (in *Inbound) validateServerTLS() error {
	t := in.TLS
	st := &serverTLS{base: &tls.Config{MinVersion: tls.VersionTLS12}}
	var e error
	if st.base.MinVersion, e = parseTLSVersion(t.MinVersion, tls.VersionTLS12); e != nil {
		return e
	}
	if st.base.MaxVersion, e = parseTLSVersion(t.MaxVersion, 0); e != nil {
		return e
	}
	if st.base.MaxVersion != 0 && st.base.MaxVersion < st.base.MinVersion {
		return errors.New("tls.max_version is below tls.min_version")
	}
	if len(t.CipherSuites) > 0 {
		if st.base.MinVersion == tls.VersionTLS13 {
			return errors.New("tls.cipher_suites only applies to TLS 1.2 (min_version is 1.3)")
		}
		known := tls12Suites()
		seen := map[uint16]bool{}
		for _, name := range t.CipherSuites {
			id, ok := known[name]
			if !ok || seen[id] {
				return fmt.Errorf("unknown, insecure or duplicate TLS 1.2 cipher suite %q", name)
			}
			seen[id] = true
			st.base.CipherSuites = append(st.base.CipherSuites, id)
		}
	}
	if len(t.ALPN) > 8 {
		return errors.New("at most 8 tls.alpn protocols")
	}
	for _, p := range t.ALPN {
		if p == "" || len(p) > 255 || p == tlscert.ALPNProto {
			return errors.New("invalid tls.alpn protocol")
		}
	}
	st.base.NextProtos = append([]string(nil), t.ALPN...)
	if t.WatchInterval != 0 && !t.Watch {
		return errors.New("tls.watch_interval requires tls.watch")
	}
	if t.Watch {
		st.watch = t.WatchInterval.value()
		if st.watch == 0 {
			st.watch = defaultWatchInterval
		}
		if st.watch < time.Second || st.watch > 24*time.Hour {
			return errors.New("tls.watch_interval must be between 1s and 24h")
		}
	}
	if (t.Cert == "") != (t.Key == "") {
		// Keep the previous message for a half-written pair.
		return errors.New("cannot load TLS certificate/key")
	}
	if t.Cert == "" && t.ACME == nil {
		return errors.New("cannot load TLS certificate/key")
	}
	if len(t.Certificates) > 64 {
		return errors.New("at most 64 tls.certificates")
	}
	pairs := []TLSCertFile{}
	if t.Cert != "" {
		pairs = append(pairs, TLSCertFile{t.Cert, t.Key})
	}
	pairs = append(pairs, t.Certificates...)
	if t.Watch && len(pairs) == 0 {
		return errors.New("tls.watch requires certificate files")
	}
	var certs []tls.Certificate
	for _, p := range pairs {
		if p.Cert == "" || p.Key == "" {
			return errors.New("tls.certificates entries need cert and key")
		}
		c, sum, e := tlscert.LoadPair(p.Cert, p.Key)
		if e != nil {
			return errors.New("cannot load TLS certificate/key")
		}
		st.files = append(st.files, tlscert.NewFilePair(p.Cert, p.Key, c, sum))
		certs = append(certs, *c)
	}
	if t.ACME != nil {
		if e := t.ACME.validate(); e != nil {
			return e
		}
		st.acme = t.ACME
	}
	cfg := st.base.Clone()
	cfg.Certificates = certs
	if len(certs) == 0 {
		// ACME only: until a certificate exists the inbound answers with an
		// ephemeral one (the running server serves the ACME certificate).
		eph, e := ephemeralTLSConfig(time.Now())
		if e != nil {
			return errors.New("cannot generate TLS certificate")
		}
		cfg.Certificates = eph.Certificates
	}
	in.tlsConfig, in.serverTLS, in.ephemeralTLS = cfg, st, false
	return nil
}

// validDomain accepts an LDH name with at least two labels, optionally with
// a leading "*." wildcard label.
func validDomain(s string) bool {
	s = strings.TrimPrefix(s, "*.")
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (a *ACMEConfig) validate() error {
	if len(a.Domains) == 0 || len(a.Domains) > 100 {
		return errors.New("tls.acme.domains needs 1..100 names")
	}
	seen := map[string]bool{}
	for i, d := range a.Domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if !validDomain(d) || seen[d] {
			return errors.New("invalid or duplicate tls.acme domain")
		}
		if strings.HasPrefix(d, "*.") && a.Challenge != tlscert.ChallengeDNS01 {
			return errors.New("wildcard tls.acme domains require dns-01")
		}
		seen[d] = true
		a.Domains[i] = d
	}
	if a.Email != "" && (len(a.Email) > 254 || !strings.Contains(a.Email, "@") || strings.ContainsAny(a.Email, " \t\r\n<>,")) {
		return errors.New("invalid tls.acme.email")
	}
	if a.Directory == "" {
		a.Directory = defaultACMEDirectory
	}
	if u, e := url.Parse(a.Directory); e != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("tls.acme.directory must be an https URL")
	}
	a.dirCA = nil
	if a.DirectoryCA != "" {
		b, e := tlscert.ReadFileLimited(a.DirectoryCA)
		pool := x509.NewCertPool()
		if e != nil || !pool.AppendCertsFromPEM(b) {
			return errors.New("cannot load tls.acme.directory_ca")
		}
		a.dirCA = pool
	}
	a.eabKey = nil
	if a.EAB != nil {
		k, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.EAB.MACKey, "="))
		if a.EAB.KeyID == "" || e != nil || len(k) == 0 {
			return errors.New("tls.acme.eab needs key_id and a base64url mac_key")
		}
		a.eabKey = k
	}
	switch a.KeyType {
	case "":
		a.KeyType = "ecdsa"
	case "ecdsa", "rsa":
	default:
		return errors.New("tls.acme.key_type must be ecdsa or rsa")
	}
	if a.Storage != "" && !filepath.IsAbs(a.Storage) {
		return errors.New("tls.acme.storage must be an absolute path")
	}
	if a.Challenge != tlscert.ChallengeHTTP01 && (a.HTTPListen != "" || a.Webroot != "") {
		return errors.New("tls.acme.http_listen/webroot apply to http-01 only")
	}
	if a.Challenge != tlscert.ChallengeDNS01 && a.DNS != nil {
		return errors.New("tls.acme.dns applies to dns-01 only")
	}
	switch a.Challenge {
	case tlscert.ChallengeHTTP01:
		if a.HTTPListen != "" && a.Webroot != "" {
			return errors.New("tls.acme.http_listen and webroot are exclusive")
		}
		if a.HTTPListen != "" {
			if _, p, e := net.SplitHostPort(a.HTTPListen); e != nil || p == "" || p == "0" {
				return errors.New("invalid tls.acme.http_listen")
			}
		}
		if a.Webroot != "" && !filepath.IsAbs(a.Webroot) {
			return errors.New("tls.acme.webroot must be an absolute path")
		}
	case tlscert.ChallengeTLSALPN01:
	case tlscert.ChallengeDNS01:
		d := a.DNS
		if d == nil || d.Provider != "cloudflare" {
			return errors.New("dns-01 requires tls.acme.dns with provider cloudflare")
		}
		if (d.APIToken == "") == (d.APITokenFile == "") {
			return errors.New("tls.acme.dns needs exactly one of api_token and api_token_file")
		}
		a.dnsToken = d.APIToken
		if d.APITokenFile != "" {
			b, e := tlscert.ReadFileLimited(d.APITokenFile)
			if e != nil || len(strings.TrimSpace(string(b))) == 0 {
				return errors.New("cannot read tls.acme.dns.api_token_file")
			}
			a.dnsToken = strings.TrimSpace(string(b))
		}
		if d.APIURL != "" {
			if u, e := url.Parse(d.APIURL); e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return errors.New("invalid tls.acme.dns.api_url")
			}
		}
		for _, r := range d.Resolvers {
			if _, _, e := net.SplitHostPort(r); e != nil {
				return errors.New("tls.acme.dns.resolvers entries are host:port")
			}
		}
		if d.PropagationTimeout != 0 && (d.PropagationTimeout.value() < time.Second || d.PropagationTimeout.value() > time.Hour) {
			return errors.New("tls.acme.dns.propagation_timeout must be between 1s and 1h")
		}
		if d.TTL != 0 && (d.TTL < 60 || d.TTL > 86400) {
			return errors.New("tls.acme.dns.ttl must be between 60 and 86400")
		}
	default:
		return errors.New("tls.acme.challenge must be http-01, tls-alpn-01 or dns-01")
	}
	return nil
}

// identity distinguishes managed certificates: equal identities share one
// manager (and its certificate) across inbounds and reloads.
func (a *ACMEConfig) identity() string {
	v := struct {
		A   ACMEConfig
		Tok string
	}{*a, a.dnsToken}
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (a *ACMEConfig) options() tlscert.Options {
	o := tlscert.Options{Domains: append([]string(nil), a.Domains...), Email: a.Email, Directory: a.Directory, DirectoryCA: a.dirCA, Challenge: a.Challenge, HTTPListen: a.HTTPListen, Webroot: a.Webroot, KeyType: a.KeyType, Storage: a.Storage, UserAgent: "kat/" + Version}
	if a.EAB != nil {
		o.EABKeyID, o.EABMACKey = a.EAB.KeyID, a.eabKey
	}
	if d := a.DNS; d != nil {
		o.DNS = &tlscert.Cloudflare{Token: a.dnsToken, ZoneID: d.ZoneID, APIURL: d.APIURL, TTL: d.TTL}
		o.DNSResolvers = d.Resolvers
		o.PropagationTimeout = d.PropagationTimeout.value()
	}
	return o
}

// ApplyDefaultStateDir sets the ACME storage of inbounds that do not
// configure one to <dir>/acme. Only the CLI calls it (like ApplyDefaultPaths).
func (c *Config) ApplyDefaultStateDir(dir string) {
	c.stateDir = dir
	for i := range c.Inbounds {
		if t := c.Inbounds[i].TLS; t != nil && t.ACME != nil && t.ACME.Storage == "" {
			t.ACME.Storage = filepath.Join(dir, "acme")
		}
	}
}
