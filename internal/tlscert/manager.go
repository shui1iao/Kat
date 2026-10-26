package tlscert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

// LetsEncrypt is the default ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// Challenge types.
const (
	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
	ChallengeDNS01     = "dns-01"
)

// ALPNProto is the ALPN protocol of TLS-ALPN-01 validation connections.
const ALPNProto = acme.ALPNProto

// Options configures one managed certificate.
type Options struct {
	Domains     []string // lowercase; a "*." wildcard requires DNS-01
	Email       string
	Directory   string         // default LetsEncrypt
	DirectoryCA *x509.CertPool // nil = system roots for the ACME server
	EABKeyID    string
	EABMACKey   []byte
	Challenge   string // http-01 | tls-alpn-01 | dns-01
	HTTPListen  string // http-01 standalone listener (default ":80")
	Webroot     string // http-01: write the challenge file here instead
	DNS         DNSProvider
	// DNSResolvers ("host:port") are asked for the TXT record before the
	// challenge is accepted; empty = the zone's authoritative name servers.
	DNSResolvers       []string
	PropagationTimeout time.Duration // default 2m
	KeyType            string        // "ecdsa" (P-256, default) | "rsa" (2048)
	Storage            string        // directory for accounts and certificates
	UserAgent          string
}

// Hooks connect a Manager to its user.
type Hooks struct {
	// Log receives one "kat event=..." line; level is "debug", "info" or "warn".
	Log func(level, line string)
	// ALPN publishes (cert != nil) or withdraws (nil) the TLS-ALPN-01
	// validation certificate of domain.
	ALPN func(domain string, cert *tls.Certificate)
}

// Manager obtains a certificate for Options.Domains, keeps it in Storage and
// renews it when a third of its lifetime is left. Certificate() returns nil
// until a certificate exists.
type Manager struct {
	Holder
	o   Options
	h   Hooks
	dir string // storage directory of this CA

	mu         sync.Mutex
	client     *acme.Client
	registered bool

	startOnce sync.Once
	cancel    context.CancelFunc
	done      chan struct{}

	Obtained atomic.Int64 // successful issuances by this manager
	Failures atomic.Int64 // failed attempts
}

// Now is the clock of renewal decisions (tests may replace it).
var Now = time.Now

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			b[i] = '_'
		}
	}
	return strings.Trim(string(b), ".")
}

// caDirName names the storage subdirectory of an ACME directory URL.
func caDirName(directory string) string {
	u, e := url.Parse(directory)
	if e != nil || u.Host == "" {
		return sanitize(directory)
	}
	name := u.Host + strings.ReplaceAll(strings.TrimSuffix(u.Path, "/"), "/", "-")
	return sanitize(name)
}

// NewManager validates o and loads a stored certificate. It performs no
// network I/O.
func NewManager(o Options, h Hooks) (*Manager, error) {
	if len(o.Domains) == 0 {
		return nil, errors.New("acme: no domains")
	}
	if o.Storage == "" || !filepath.IsAbs(o.Storage) {
		return nil, errors.New("acme: storage must be an absolute directory")
	}
	if o.Directory == "" {
		o.Directory = LetsEncrypt
	}
	if o.HTTPListen == "" {
		o.HTTPListen = ":80"
	}
	if o.PropagationTimeout == 0 {
		o.PropagationTimeout = 2 * time.Minute
	}
	if h.Log == nil {
		h.Log = func(string, string) {}
	}
	m := &Manager{o: o, h: h, dir: filepath.Join(o.Storage, caDirName(o.Directory))}
	if c := m.loadStored(); c != nil {
		m.Store(c)
	}
	return m, nil
}

func (m *Manager) certDir() string {
	return filepath.Join(m.dir, "certificates", sanitize(strings.ReplaceAll(m.o.Domains[0], "*", "_wildcard_")))
}

func (m *Manager) domainsList() string { return strings.Join(m.o.Domains, ",") }

// covers reports whether leaf is valid for every configured domain.
func (m *Manager) covers(leaf *x509.Certificate) bool {
	for _, d := range m.o.Domains {
		if !slices.Contains(leaf.DNSNames, d) {
			return false
		}
	}
	return true
}

// loadStored returns the stored certificate when it covers all domains and
// has not expired.
func (m *Manager) loadStored() *tls.Certificate {
	dir := m.certDir()
	c, _, e := LoadPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if e != nil || !m.covers(c.Leaf) || Now().After(c.Leaf.NotAfter) {
		return nil
	}
	return c
}

// RenewAt is the renewal time of leaf: when a third of its lifetime is left.
func RenewAt(leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Add(-life / 3)
}

// Start begins managing (first issuance when nothing is stored, then
// renewals). ctx ends the manager.
func (m *Manager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		ctx, m.cancel = context.WithCancel(ctx)
		m.done = make(chan struct{})
		go m.run(ctx)
	})
}

// Stop ends the manager and waits for it (a no-op when never started).
func (m *Manager) Stop() {
	m.startOnce.Do(func() {})
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
}

// backoff returns the wait after the n-th consecutive failure (n >= 1). It
// scales with the certificate lifetime so that short-lived test
// certificates are retried quickly: base = lifetime/20 within [5s, 1m],
// doubling up to min(6h, lifetime/6) but at least the base.
func backoff(n int, life time.Duration) time.Duration {
	if life <= 0 {
		life = 90 * 24 * time.Hour
	}
	base := min(max(life/20, 5*time.Second), time.Minute)
	limit := max(min(6*time.Hour, life/6), base)
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

func (m *Manager) run(ctx context.Context) {
	defer close(m.done)
	failures := 0
	for {
		cur := m.Certificate()
		now := Now()
		var wait time.Duration
		if cur != nil && now.Before(RenewAt(cur.Leaf)) {
			wait = min(RenewAt(cur.Leaf).Sub(now), time.Hour)
		} else {
			// Another process (or a previous run) may have renewed it.
			if st := m.loadStored(); st != nil && now.Before(RenewAt(st.Leaf)) && !SamePEM(st, cur) {
				m.Store(st)
				m.h.Log("info", "kat event=acme_certificate_loaded domains="+m.domainsList()+" not_after="+st.Leaf.NotAfter.UTC().Format(time.RFC3339))
				continue
			}
			kind := "obtain"
			life := 90 * 24 * time.Hour
			if cur != nil {
				kind = "renew"
				life = cur.Leaf.NotAfter.Sub(cur.Leaf.NotBefore)
			}
			start := time.Now()
			c, e := m.obtain(ctx)
			if ctx.Err() != nil {
				return
			}
			if e != nil {
				failures++
				m.Failures.Add(1)
				wait = backoff(failures, life)
				line := "kat event=acme_" + kind + "_failed domains=" + m.domainsList() + " attempt=" + strconv.Itoa(failures) + " retry_in=" + wait.String()
				if cur != nil {
					line += " current_not_after=" + cur.Leaf.NotAfter.UTC().Format(time.RFC3339)
					if now.After(cur.Leaf.NotAfter) {
						line += " current_expired=true"
					}
				}
				m.h.Log("warn", line+" reason="+token(e.Error(), 300))
			} else {
				failures = 0
				m.Obtained.Add(1)
				m.Store(c)
				m.h.Log("info", "kat event=acme_certificate_"+map[string]string{"obtain": "obtained", "renew": "renewed"}[kind]+" domains="+m.domainsList()+" not_after="+c.Leaf.NotAfter.UTC().Format(time.RFC3339)+" renew_at="+RenewAt(c.Leaf).UTC().Format(time.RFC3339)+" duration_ms="+strconv.FormatInt(time.Since(start).Milliseconds(), 10))
				continue
			}
		}
		t := time.NewTimer(max(wait, time.Second))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// token makes s safe for one key=value log field.
func token(s string, n int) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() >= n {
			break
		}
		if c < 0x21 || c == 0x7f || c == '=' || c == '"' {
			c = '_'
		}
		b.WriteRune(c)
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// ---- storage ----

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	_, e = f.Write(data)
	if e == nil {
		e = f.Chmod(mode)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(tmp, path)
	}
	if e != nil {
		os.Remove(tmp)
	}
	return e
}

func marshalKey(k crypto.Signer) ([]byte, error) {
	der, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM key")
	}
	k, e := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if e != nil {
		return nil, e
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key")
	}
	return s, nil
}

// accountKey loads or creates the account key of (directory, email).
func (m *Manager) accountKey() (crypto.Signer, error) {
	name := "default"
	if m.o.Email != "" {
		name = sanitize(m.o.Email)
	}
	path := filepath.Join(m.dir, "accounts", name+".key")
	if b, e := ReadFileLimited(path); e == nil {
		return parseKey(b)
	} else if !os.IsNotExist(e) {
		return nil, fmt.Errorf("cannot read account key: %w", e)
	}
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	b, e := marshalKey(k)
	if e != nil {
		return nil, e
	}
	if e := writeFileAtomic(path, b, 0o600); e != nil {
		return nil, fmt.Errorf("cannot store account key: %w", e)
	}
	m.h.Log("info", "kat event=acme_account_key_created directory="+token(m.o.Directory, 200))
	return k, nil
}

func (m *Manager) newCertKey() (crypto.Signer, error) {
	if m.o.KeyType == "rsa" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ---- ACME ----

func (m *Manager) acmeClient(ctx context.Context) (*acme.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil && m.registered {
		return m.client, nil
	}
	key, e := m.accountKey()
	if e != nil {
		return nil, e
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if m.o.DirectoryCA != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: m.o.DirectoryCA, MinVersion: tls.VersionTLS12}
	}
	c := &acme.Client{Key: key, DirectoryURL: m.o.Directory, UserAgent: m.o.UserAgent, HTTPClient: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
	acct := &acme.Account{}
	if m.o.Email != "" {
		acct.Contact = []string{"mailto:" + m.o.Email}
	}
	if m.o.EABKeyID != "" {
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: m.o.EABKeyID, Key: m.o.EABMACKey}
	}
	if _, e := c.Register(ctx, acct, acme.AcceptTOS); e != nil && !errors.Is(e, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("account registration: %w", e)
	} else if e == nil {
		m.h.Log("info", "kat event=acme_account_registered directory="+token(m.o.Directory, 200))
	}
	m.client, m.registered = c, true
	return c, nil
}

func (m *Manager) resetClient() {
	m.mu.Lock()
	m.client, m.registered = nil, false
	m.mu.Unlock()
}

func accountMissing(e error) bool {
	var ae *acme.Error
	return errors.As(e, &ae) && (ae.ProblemType == "urn:ietf:params:acme:error:accountDoesNotExist" || ae.StatusCode == http.StatusUnauthorized)
}

// obtain runs one complete order and stores the certificate.
func (m *Manager) obtain(parent context.Context) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	c, e := m.acmeClient(ctx)
	if e != nil {
		return nil, e
	}
	order, e := c.AuthorizeOrder(ctx, acme.DomainIDs(m.o.Domains...))
	if e != nil && accountMissing(e) {
		// The CA forgot the account (e.g. a test CA restarted): register again.
		m.resetClient()
		if c, e = m.acmeClient(ctx); e != nil {
			return nil, e
		}
		order, e = c.AuthorizeOrder(ctx, acme.DomainIDs(m.o.Domains...))
	}
	if e != nil {
		return nil, fmt.Errorf("new order: %w", e)
	}
	for _, u := range order.AuthzURLs {
		if e := m.authorize(ctx, c, u); e != nil {
			return nil, e
		}
	}
	orderURL := order.URI // later order responses may lack the Location header
	if order, e = c.WaitOrder(ctx, orderURL); e != nil {
		return nil, fmt.Errorf("order: %w", e)
	}
	key, e := m.newCertKey()
	if e != nil {
		return nil, e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: strings.TrimPrefix(m.o.Domains[0], "*.")}, DNSNames: m.o.Domains}, key)
	if e != nil {
		return nil, e
	}
	der, _, e := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if e != nil {
		// A CA may answer the finalization with "processing" and without a
		// Location header (Pebble does): x/crypto/acme then polls an empty
		// URL. Poll the known order URL instead and fetch the certificate.
		if o, we := c.WaitOrder(ctx, orderURL); we == nil && o.Status == acme.StatusValid && o.CertURL != "" {
			der, e = c.FetchCert(ctx, o.CertURL, true)
		}
	}
	if e != nil {
		return nil, fmt.Errorf("finalize: %w", e)
	}
	var chain []byte
	for _, d := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	kb, e := marshalKey(key)
	if e != nil {
		return nil, e
	}
	cert, e := ParsePair(chain, kb)
	if e != nil || !m.covers(cert.Leaf) {
		return nil, errors.New("issued certificate does not match the order")
	}
	dir := m.certDir()
	if e := writeFileAtomic(filepath.Join(dir, "key.pem"), kb, 0o600); e != nil {
		return nil, fmt.Errorf("cannot store certificate: %w", e)
	}
	if e := writeFileAtomic(filepath.Join(dir, "cert.pem"), chain, 0o600); e != nil {
		return nil, fmt.Errorf("cannot store certificate: %w", e)
	}
	return cert, nil
}

func (m *Manager) authorize(ctx context.Context, c *acme.Client, u string) error {
	z, e := c.GetAuthorization(ctx, u)
	if e != nil {
		return fmt.Errorf("authorization: %w", e)
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, ch := range z.Challenges {
		if ch.Type == m.o.Challenge {
			chal = ch
			break
		}
	}
	domain := z.Identifier.Value
	if chal == nil {
		return fmt.Errorf("the CA offers no %s challenge for %s", m.o.Challenge, domain)
	}
	cleanup, e := m.present(ctx, c, domain, chal)
	if e != nil {
		return fmt.Errorf("%s present for %s: %w", m.o.Challenge, domain, e)
	}
	defer cleanup()
	if _, e := c.Accept(ctx, chal); e != nil {
		return fmt.Errorf("accept %s: %w", m.o.Challenge, e)
	}
	if _, e := c.WaitAuthorization(ctx, z.URI); e != nil {
		return fmt.Errorf("%s validation for %s: %w", m.o.Challenge, domain, e)
	}
	return nil
}

func (m *Manager) present(ctx context.Context, c *acme.Client, domain string, chal *acme.Challenge) (func(), error) {
	switch m.o.Challenge {
	case ChallengeHTTP01:
		path := c.HTTP01ChallengePath(chal.Token)
		body, e := c.HTTP01ChallengeResponse(chal.Token)
		if e != nil {
			return nil, e
		}
		if m.o.Webroot != "" {
			file := filepath.Join(m.o.Webroot, filepath.FromSlash(strings.TrimPrefix(path, "/")))
			if e := os.MkdirAll(filepath.Dir(file), 0o755); e != nil {
				return nil, e
			}
			if e := os.WriteFile(file, []byte(body), 0o644); e != nil {
				return nil, e
			}
			return func() { os.Remove(file) }, nil
		}
		r, e := acquireHTTP(m.o.HTTPListen)
		if e != nil {
			return nil, fmt.Errorf("cannot listen on %s: %w", m.o.HTTPListen, e)
		}
		r.set(path, body)
		return func() { r.del(path); r.release() }, nil
	case ChallengeTLSALPN01:
		cert, e := c.TLSALPN01ChallengeCert(chal.Token, domain)
		if e != nil {
			return nil, e
		}
		if m.h.ALPN == nil {
			return nil, errors.New("TLS-ALPN-01 is not served")
		}
		m.h.ALPN(domain, &cert)
		return func() { m.h.ALPN(domain, nil) }, nil
	case ChallengeDNS01:
		if m.o.DNS == nil {
			return nil, errors.New("no DNS provider")
		}
		value, e := c.DNS01ChallengeRecord(chal.Token)
		if e != nil {
			return nil, e
		}
		fqdn := "_acme-challenge." + domain
		id, e := m.o.DNS.Present(ctx, fqdn, value)
		if e != nil {
			return nil, e
		}
		m.h.Log("debug", "kat event=acme_dns_record_created name="+fqdn)
		cleanup := func() {
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if e := m.o.DNS.CleanUp(cctx, fqdn, id); e != nil {
				m.h.Log("warn", "kat event=acme_dns_cleanup_failed name="+fqdn+" reason="+token(e.Error(), 200))
			} else {
				m.h.Log("debug", "kat event=acme_dns_record_deleted name="+fqdn)
			}
		}
		if e := m.waitTXT(ctx, fqdn, value); e != nil {
			m.h.Log("warn", "kat event=acme_dns_propagation_unconfirmed name="+fqdn+" reason="+token(e.Error(), 200))
		}
		return cleanup, nil
	}
	return nil, errors.New("unsupported challenge")
}

// waitTXT waits until every checked name server returns value for fqdn.
func (m *Manager) waitTXT(ctx context.Context, fqdn, value string) error {
	ctx, cancel := context.WithTimeout(ctx, m.o.PropagationTimeout)
	defer cancel()
	servers := m.o.DNSResolvers
	for {
		if len(servers) == 0 {
			servers = authoritative(ctx, fqdn)
		}
		if len(servers) > 0 && allHave(ctx, servers, fqdn, value) {
			return nil
		}
		select {
		case <-ctx.Done():
			if len(servers) == 0 {
				return errors.New("no name server found")
			}
			return errors.New("TXT record not visible before the propagation timeout")
		case <-time.After(2 * time.Second):
		}
	}
}

// authoritative returns the name servers (ip:53) of the closest enclosing
// zone of fqdn.
func authoritative(ctx context.Context, fqdn string) []string {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 1; i+1 < len(labels); i++ {
		ns, e := net.DefaultResolver.LookupNS(ctx, strings.Join(labels[i:], ".")+".")
		if e != nil || len(ns) == 0 {
			continue
		}
		var out []string
		for _, n := range ns {
			ips, e := net.DefaultResolver.LookupIPAddr(ctx, n.Host)
			if e != nil {
				continue
			}
			for _, ip := range ips {
				out = append(out, net.JoinHostPort(ip.IP.String(), "53"))
				break
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func allHave(ctx context.Context, servers []string, fqdn, value string) bool {
	for _, s := range servers {
		srv := s
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv)
		}}
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		txts, e := r.LookupTXT(qctx, strings.TrimSuffix(fqdn, ".")+".")
		cancel()
		if e != nil || !slices.Contains(txts, value) {
			return false
		}
	}
	return true
}
