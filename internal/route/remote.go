package route

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// source is one file-backed dataset (a rule set or the GeoIP database) with
// an optional remote https origin.
type source struct {
	kind     string // "rule_set" | "geoip" | "geosite" | "asn"
	name     string // rule set name ("" for geoip)
	path     string
	url      string
	via      string
	maxBytes int
	interval time.Duration
	mtime    time.Time // of the local file when it loaded successfully
	stamp    string    // parse parameters, part of the parsed-data cache key

	parse func([]byte) (any, error)
	check func(any) error // called with Engine.mu held
	swap  func(any)       // called with Engine.mu held; emits the loaded event
}

// failure classes reported in *_update_failed events.
const (
	classMissing  = "missing"
	classRead     = "read"
	classTooLarge = "too_large"
	classParse    = "parse"
	classLimit    = "limit"
	classStatus   = "http_status"
	classDial     = "dial"
	classTLS      = "tls"
	classTimeout  = "timeout"
	classNetwork  = "network"
	classWrite    = "write"
	classUnsup    = "unsupported"
)

func (e *Engine) failed(s *source, class string) { e.failedDetail(s, class, nil) }

// failedDetail emits the *_update_failed event; unsupported content carries
// a detail (line or field and the unsupported rule type or option).
func (e *Engine) failedDetail(s *source, class string, err error) {
	var kv []string
	if s.kind == "rule_set" {
		kv = append(kv, "name", s.name)
	}
	kv = append(kv, "class", class)
	var u *unsupportedError
	if errors.As(err, &u) {
		kv = append(kv, "detail", u.msg)
	}
	e.events.Emit(s.kind+"_update_failed", kv...)
}

func dataClass(err error) string {
	var u *unsupportedError
	switch {
	case errors.Is(err, errLimit):
		return classLimit
	case errors.Is(err, errTooLarge):
		return classTooLarge
	case errors.As(err, &u):
		return classUnsup
	}
	return classParse
}

func readLimited(path string, max int) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, errors.New("route: not a regular file")
	}
	if fi.Size() > int64(max) {
		return nil, nil, errTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > max {
		return nil, nil, errTooLarge
	}
	return b, fi, nil
}

// loadLocal loads the source's file at startup (Engine.mu held). A missing
// file is silent when a url will fetch it; every other failure is an event.
func (e *Engine) loadLocal(s *source) {
	b, fi, err := readLimited(s.path, s.maxBytes)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if s.url == "" {
				e.failed(s, classMissing)
			}
		case errors.Is(err, errTooLarge):
			e.failed(s, classTooLarge)
		default:
			e.failed(s, classRead)
		}
		return
	}
	key := cacheKey(s, b)
	v := cacheGet(s.path, key)
	if v == nil {
		v, err = s.parse(b)
	}
	if err == nil {
		err = s.check(v)
	}
	if err != nil {
		e.failedDetail(s, dataClass(err), err)
		return
	}
	cachePut(s.path, key, v)
	s.mtime = fi.ModTime()
	s.swap(v)
}

// run refreshes one source until ctx ends: first after delay, then every
// interval after success; failures back off 1m, 2m, 4m... capped at interval.
func (e *Engine) run(ctx context.Context, s *source, delay time.Duration) {
	defer e.wg.Done()
	backoff := e.backoffBase
	for {
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		if e.update(ctx, s) {
			delay, backoff = s.interval, e.backoffBase
			continue
		}
		if ctx.Err() != nil {
			return
		}
		delay = min(backoff, s.interval)
		backoff = min(backoff*2, s.interval)
	}
}

// update downloads, validates, atomically writes and then swaps the data.
// On any failure the previous data and file stay untouched.
func (e *Engine) update(ctx context.Context, s *source) bool {
	b, class := e.download(ctx, s)
	if class != "" {
		if ctx.Err() == nil {
			e.failed(s, class)
		}
		return false
	}
	v, err := s.parse(b)
	if err != nil {
		e.failedDetail(s, dataClass(err), err)
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := s.check(v); err != nil {
		e.failedDetail(s, dataClass(err), err)
		return false
	}
	if err := writeAtomic(s.path, b); err != nil {
		e.failed(s, classWrite)
		return false
	}
	cachePut(s.path, cacheKey(s, b), v)
	s.swap(v)
	return true
}

func writeAtomic(path string, b []byte) (err error) {
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// A unique temporary name: an engine of a superseded generation may
	// still be finishing a download of the same source.
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err = f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// download fetches the source over https through the via outbound with
// standard certificate verification. It returns the body or a failure class.
func (e *Engine) download(ctx context.Context, s *source) ([]byte, string) {
	dial, err := e.dial(s.via)
	if err != nil || dial == nil {
		return nil, classDial
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		TLSClientConfig:        &tls.Config{RootCAs: e.rootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    30 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   e.fetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
				return errors.New("route: redirect refused")
			}
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(ctx, e.fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, classNetwork
	}
	req.Header.Set("User-Agent", "Kat")
	resp, err := client.Do(req)
	if err != nil {
		return nil, netClass(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, classStatus
	}
	if resp.ContentLength > int64(s.maxBytes) {
		return nil, classTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.maxBytes)+1))
	if err != nil {
		return nil, netClass(err)
	}
	if len(b) > s.maxBytes {
		return nil, classTooLarge
	}
	return b, ""
}

func netClass(err error) string {
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var ne net.Error
	switch {
	case errors.As(err, &unknown), errors.As(err, &host), errors.As(err, &invalid), errors.As(err, &verify), errors.As(err, &record):
		return classTLS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return classTimeout
	}
	return classNetwork
}
