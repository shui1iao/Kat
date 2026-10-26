package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/provider"
)

// ProviderConfig is one root "providers" entry (subscription node set).
type ProviderConfig struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`                     // http | file
	URL           string            `json:"url,omitempty"`            // http: subscription URL
	Path          string            `json:"path,omitempty"`           // file: source; http: cache (default in the state directory)
	Interval      Duration          `json:"interval,omitempty"`       // http: refresh (default 1h); file: re-read (default only on reload)
	Timeout       Duration          `json:"timeout,omitempty"`        // http: whole request, default 30s
	Via           string            `json:"via,omitempty"`            // http: outbound or group used to fetch, default direct
	UserAgent     string            `json:"user_agent,omitempty"`     // http: default "clash.meta"
	Headers       map[string]string `json:"headers,omitempty"`        // http: extra request headers
	Format        string            `json:"format,omitempty"`         // auto (default) | clash | uri | sing-box
	Filter        string            `json:"filter,omitempty"`         // keep nodes whose name matches (RE2, ` separates alternatives)
	ExcludeFilter string            `json:"exclude_filter,omitempty"` // drop nodes whose name matches
	ExcludeType   string            `json:"exclude_type,omitempty"`   // drop node types, e.g. "socks5|shadowsocks"
}

func (o *ProviderConfig) UnmarshalJSON(b []byte) error {
	type plain ProviderConfig
	var p plain
	if e := strictPlain(b, &p); e != nil {
		return e
	}
	*o = ProviderConfig(p)
	return nil
}

const (
	maxProviders            = 16
	maxProviderNodesTotal   = 4096
	defaultProviderInterval = time.Hour
	defaultProviderTimeout  = 30 * time.Second
	defaultProviderUA       = "clash.meta"
	maxProviderHeaders      = 32
)

var providerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// validateProviders statically checks the providers block (no I/O).
func (c *Config) validateProviders() error {
	if len(c.Providers) > maxProviders {
		return fmt.Errorf("at most %d providers", maxProviders)
	}
	seen := map[string]bool{}
	for i := range c.Providers {
		p := &c.Providers[i]
		fail := func(f string, a ...any) error {
			return fmt.Errorf("provider %q: "+f, append([]any{p.Name}, a...)...)
		}
		if !providerNameRE.MatchString(p.Name) || seen[p.Name] {
			return fmt.Errorf("provider %d: name must be 1..64 of A-Z a-z 0-9 . _ - (unique)", i)
		}
		seen[p.Name] = true
		if p.Path != "" && !filepath.IsAbs(p.Path) {
			return fail("path must be absolute")
		}
		if p.Interval != 0 && (p.Interval.value() < time.Second || p.Interval.value() > 7*24*time.Hour) {
			return fail("interval must be between 1s and 168h")
		}
		switch p.Type {
		case "http":
			u, e := url.Parse(p.URL)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fail("url must be an absolute http or https URL")
			}
			if p.Timeout != 0 && (p.Timeout.value() < time.Second || p.Timeout.value() > 5*time.Minute) {
				return fail("timeout must be between 1s and 5m")
			}
			if len(p.Headers) > maxProviderHeaders {
				return fail("too many headers")
			}
			for k, v := range p.Headers {
				if !validHeaderName(k) || strings.ContainsAny(v, "\r\n\x00") {
					return fail("invalid header %q", k)
				}
			}
			if strings.ContainsAny(p.UserAgent, "\r\n\x00") {
				return fail("invalid user_agent")
			}
			if p.Via == "reject" {
				return fail("via cannot be reject")
			}
		case "file":
			if p.Path == "" {
				return fail("file providers need path")
			}
			if p.URL != "" || p.Via != "" || p.UserAgent != "" || len(p.Headers) != 0 || p.Timeout != 0 {
				return fail("url, via, user_agent, headers and timeout are http-only")
			}
		default:
			return fail("type must be http or file")
		}
		switch p.Format {
		case "", provider.FormatAuto, provider.FormatClash, provider.FormatURI, provider.FormatSingBox:
		default:
			return fail("format must be auto, clash, uri or sing-box")
		}
		if _, e := providerFilter(*p); e != nil {
			return fail("%v", e)
		}
	}
	return nil
}

func validHeaderName(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	for _, c := range k {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", c) {
			return false
		}
	}
	return true
}

func providerFilter(p ProviderConfig) (func(name, typ string) bool, error) {
	return group.MemberFilter(group.Options{Filter: p.Filter, ExcludeFilter: p.ExcludeFilter, ExcludeType: p.ExcludeType})
}

// cachePath returns the http cache file ("" = no cache). Default: state
// directory next to the statistics file, keyed by provider name + URL hash.
func (p ProviderConfig) cachePath(statsFile string) string {
	if p.Type != "http" {
		return ""
	}
	if p.Path != "" {
		return p.Path
	}
	if statsFile == "" {
		return ""
	}
	dir, base := filepath.Split(statsFile)
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".json"), ".stats")
	h := sha256.Sum256([]byte(p.URL))
	return filepath.Join(dir, base+".providers", p.Name+"-"+hex.EncodeToString(h[:4])+".cache")
}

// sourceKey identifies what a provider fetches; an unchanged key keeps the
// running provider (and its nodes) across reloads.
func (p ProviderConfig) sourceKey(statsFile string) string {
	q := p
	q.Filter, q.ExcludeFilter, q.ExcludeType = "", "", ""
	b, _ := json.Marshal(struct {
		P     ProviderConfig
		Cache string
	}{q, p.cachePath(statsFile)})
	return string(b)
}

func (c *Config) statsFile() string {
	if c.Stats == nil {
		return ""
	}
	return c.Stats.File
}

// providerRT is one running provider. It belongs to the core and outlives
// generations: an update that changes the node set installs a new
// generation; existing connections keep the generation (and nodes) they
// started with.
type providerRT struct {
	k     *core
	cfg   ProviderConfig
	key   string
	cache string

	mu       sync.Mutex
	hash     [32]byte
	res      provider.Result
	loaded   bool
	source   string // file | cache | fetch | none
	updated  time.Time
	attempt  time.Time
	lastErr  string
	failures int64
	updates  int64

	cancel context.CancelFunc
	done   chan struct{}
}

func newProviderRT(k *core, p ProviderConfig, statsFile string) *providerRT {
	return &providerRT{k: k, cfg: p, key: p.sourceKey(statsFile), cache: p.cachePath(statsFile), source: "none"}
}

// loadLocal reads the file (file providers) or the cache (http providers).
func (p *providerRT) loadLocal() (provider.Result, error) {
	path := p.cfg.Path
	if p.cfg.Type == "http" {
		path = p.cache
		if path == "" {
			return provider.Result{}, nil
		}
	}
	b, e := readLimited(path)
	if e != nil {
		if p.cfg.Type == "http" && errors.Is(e, os.ErrNotExist) {
			return provider.Result{}, nil
		}
		return provider.Result{}, e
	}
	res, e := provider.Parse(b, p.cfg.Format)
	if e == nil && len(res.Nodes) == 0 {
		e = errors.New("no usable node")
	}
	if e != nil {
		return res, e
	}
	st, _ := os.Stat(path)
	p.mu.Lock()
	p.res, p.hash, p.loaded = res, sha256.Sum256(b), true
	p.source = "file"
	if p.cfg.Type == "http" {
		p.source = "cache"
	}
	if st != nil {
		p.updated = st.ModTime()
	}
	p.mu.Unlock()
	return res, nil
}

func readLimited(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, provider.MaxSize+1))
	if e != nil {
		return nil, e
	}
	if len(b) > provider.MaxSize {
		return nil, fmt.Errorf("larger than %d bytes", provider.MaxSize)
	}
	return b, nil
}

func (p *providerRT) snapshot() (provider.Result, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.res, p.loaded
}

func (p *providerRT) start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	p.done = make(chan struct{})
	go p.run(ctx)
}

func (p *providerRT) stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *providerRT) interval() time.Duration {
	if p.cfg.Interval != 0 {
		return p.cfg.Interval.value()
	}
	if p.cfg.Type == "http" {
		return defaultProviderInterval
	}
	return 0
}

func (p *providerRT) run(ctx context.Context) {
	defer close(p.done)
	iv := p.interval()
	if iv == 0 {
		return // file provider without interval: re-read on reload only
	}
	wait := iv
	if p.cfg.Type == "http" {
		p.mu.Lock()
		age := time.Since(p.updated)
		fresh := p.loaded && age >= 0 && age < iv
		p.mu.Unlock()
		wait = 0
		if fresh {
			wait = iv - age
		}
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.update(ctx)
		t.Reset(iv)
	}
}

// update fetches (http) or re-reads (file) once. A failure keeps the
// previous nodes; a changed node set asks the core for a new generation.
func (p *providerRT) update(ctx context.Context) {
	var b []byte
	var e error
	if p.cfg.Type == "http" {
		b, e = p.fetch(ctx)
	} else {
		b, e = readLimited(p.cfg.Path)
	}
	if ctx.Err() != nil {
		return
	}
	var res provider.Result
	if e == nil {
		res, e = provider.Parse(b, p.cfg.Format)
		if e == nil && len(res.Nodes) == 0 {
			e = errors.New("no usable node")
		}
	}
	now := time.Now()
	p.mu.Lock()
	p.attempt = now
	if e != nil {
		p.failures++
		p.lastErr = e.Error()
		kept := len(p.res.Nodes)
		p.mu.Unlock()
		p.k.notice(levelWarn, "kat event=provider_update_failed provider="+p.cfg.Name+" action=keep_previous nodes="+strconv.Itoa(kept)+" reason="+eventToken(e.Error(), 200))
		for _, line := range skippedLines(p.cfg.Name, res) {
			p.k.notice(levelWarn, line)
		}
		return
	}
	h := sha256.Sum256(b)
	changed := !p.loaded || h != p.hash
	p.lastErr = ""
	p.updated = now
	p.updates++
	if p.cfg.Type == "http" {
		p.source = "fetch"
	} else {
		p.source = "file"
	}
	if changed {
		p.res, p.hash, p.loaded = res, h, true
	}
	p.mu.Unlock()
	if p.cache != "" {
		if changed {
			if e := writeFileAtomic(p.cache, b); e != nil {
				p.k.notice(levelWarn, "kat event=provider_cache_failed provider="+p.cfg.Name+" reason=io")
			}
		} else {
			_ = os.Chtimes(p.cache, now, now)
		}
	}
	if !changed {
		p.k.notice(levelDebug, "kat event=provider_unchanged provider="+p.cfg.Name)
		return
	}
	p.k.notice(levelInfo, "kat event=provider_updated provider="+p.cfg.Name+" format="+res.Format+" nodes="+strconv.Itoa(len(res.Nodes))+" skipped="+strconv.Itoa(len(res.Skipped)))
	for _, line := range skippedLines(p.cfg.Name, res) {
		p.k.notice(levelWarn, line)
	}
	p.k.requestRebuild()
}

func (p *providerRT) fetch(ctx context.Context) ([]byte, error) {
	g := p.k.gen.Load()
	if g == nil || !g.tryRef() {
		return nil, errors.New("server not running")
	}
	defer g.unref()
	dial, e := g.rt.dialVia(p.cfg.Via)
	if e != nil {
		return nil, fmt.Errorf("via %q is not available", p.cfg.Via)
	}
	timeout := defaultProviderTimeout
	if p.cfg.Timeout != 0 {
		timeout = p.cfg.Timeout.value()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{Proxy: nil, DialContext: dial, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.URL, nil)
	if e != nil {
		return nil, e
	}
	ua := p.cfg.UserAgent
	if ua == "" {
		ua = defaultProviderUA
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, e := client.Do(req)
	if e != nil {
		var ue *url.Error // the URL may carry a token: report the cause only
		if errors.As(e, &ue) {
			e = ue.Err
		}
		return nil, fmt.Errorf("request failed: %v", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, provider.MaxSize+1))
	if e != nil {
		return nil, fmt.Errorf("read failed: %v", e)
	}
	if len(b) > provider.MaxSize {
		return nil, fmt.Errorf("larger than %d bytes", provider.MaxSize)
	}
	return b, nil
}

func skippedLines(name string, res provider.Result) []string {
	var out []string
	for _, s := range res.Skipped {
		out = append(out, "kat event=provider_node_skipped provider="+name+" node="+eventToken(s.Name, 128)+" type="+eventToken(s.Type, 32)+" reason="+eventToken(s.Reason, 200))
	}
	for _, r := range res.Renamed {
		out = append(out, "kat event=provider_node_renamed provider="+name+" from="+eventToken(r[0], 128)+" to="+eventToken(r[1], 128))
	}
	return out
}

// requestRebuild asks for a new generation with the current provider nodes
// (coalesced; served by rebuildLoop). rebuildCh: make(chan struct{}, 1).
func (k *core) requestRebuild() {
	select {
	case k.rebuildCh <- struct{}{}:
	default:
	}
}

// rebuildLoop: start in Start after the first commit. Server.reload(trigger,
// reread) is the planned refactor of Reload: load = re-parse Config.raw of
// the current generation (NOT re-reading the file), expand, Validate,
// prepare, commit, installProviders.
func (k *core) rebuildLoop() {
	for {
		select {
		case <-k.ctx.Done():
			return
		case <-k.rebuildCh:
		}
		if g := k.gen.Load(); g != nil {
			_, _ = g.reload("provider", false)
		}
	}
}

// providerPlan is the provider set of a prepared generation.
type providerPlan struct {
	next  map[string]*providerRT
	fresh []*providerRT // created for this generation (loops not started)
	notes []string
}

// syncProviders builds the provider set for c. reread: file providers are
// read again (start and reload; not for provider-triggered rebuilds).
func (k *core) syncProviders(c *Config, reread bool) *providerPlan {
	pl := &providerPlan{next: map[string]*providerRT{}}
	sf := c.statsFile()
	k.provMu.Lock()
	cur := k.providers
	k.provMu.Unlock()
	for _, pc := range c.Providers {
		key := pc.sourceKey(sf)
		old := cur[pc.Name]
		if old != nil && old.key == key && !(reread && pc.Type == "file") {
			pl.next[pc.Name] = old
			continue
		}
		p := newProviderRT(k, pc, sf)
		if old != nil && old.key == key {
			old.mu.Lock() // re-read of an unchanged file provider: previous state is the fallback
			p.res, p.hash, p.loaded, p.source, p.updated = old.res, old.hash, old.loaded, old.source, old.updated
			p.failures, p.updates, p.lastErr = old.failures, old.updates, old.lastErr
			old.mu.Unlock()
		}
		prevHash, hadPrev := p.hash, p.loaded
		if rejected, e := p.loadLocal(); e != nil {
			p.mu.Lock()
			p.failures++
			p.lastErr = e.Error()
			kept := len(p.res.Nodes)
			p.mu.Unlock()
			pl.notes = append(pl.notes, skippedLines(pc.Name, rejected)...)
			pl.notes = append(pl.notes, "kat event=provider_load_failed provider="+pc.Name+" action=keep_previous nodes="+strconv.Itoa(kept)+" reason="+eventToken(e.Error(), 200))
		} else if res, ok := p.snapshot(); ok && (!hadPrev || prevHash != p.hash) {
			pl.notes = append(pl.notes, "kat event=provider_loaded provider="+pc.Name+" source="+p.source+" format="+res.Format+" nodes="+strconv.Itoa(len(res.Nodes))+" skipped="+strconv.Itoa(len(res.Skipped)))
			pl.notes = append(pl.notes, skippedLines(pc.Name, res)...)
		} else if !ok && pc.Type == "http" {
			pl.notes = append(pl.notes, "kat event=provider_empty provider="+pc.Name+" reason=no_cache action=fetch")
		}
		pl.next[pc.Name] = p
		pl.fresh = append(pl.fresh, p)
	}
	return pl
}

// installProviders makes pl the running provider set (call after commit).
func (k *core) installProviders(pl *providerPlan) {
	if pl == nil {
		return
	}
	k.provMu.Lock()
	old := k.providers
	k.providers = pl.next
	k.provMu.Unlock()
	for name, p := range old {
		if pl.next[name] != p {
			p.stop()
			if p.done != nil {
				<-p.done
			}
		}
	}
	for _, p := range pl.fresh {
		p.start(k.ctx)
	}
	for _, line := range pl.notes {
		lv := levelInfo
		if strings.Contains(line, "_failed") || strings.Contains(line, "_skipped") {
			lv = levelWarn
		}
		k.notice(lv, line)
	}
}

func (k *core) stopProviders() {
	k.provMu.Lock()
	list := make([]*providerRT, 0, len(k.providers))
	for _, p := range k.providers {
		list = append(list, p)
		p.stop()
	}
	k.provMu.Unlock()
	for _, p := range list {
		if p.done != nil {
			<-p.done
		}
	}
}

// expandProviders adds the provider nodes to c.Outbounds and resolves the
// dynamic members of every group (use, include_all*, filters). No network
// I/O. c must be the configuration as loaded (unexpanded).
func expandProviders(c *Config, provs map[string]*providerRT) []string {
	var notes []string
	written := len(c.Outbounds)
	taken := map[string]bool{"direct": true, "reject": true}
	types := map[string]string{}
	for _, o := range c.Outbounds {
		taken[o.Name] = true
		types[o.Name] = o.Type
	}
	for _, g := range c.Groups {
		taken[g.Name] = true
	}
	outs := append([]OutboundConfig(nil), c.Outbounds...)
	byProvider := map[string][]string{}
	total := 0
	for _, pc := range c.Providers {
		p := provs[pc.Name]
		if p == nil {
			continue
		}
		res, _ := p.snapshot()
		keep, _ := providerFilter(pc)
		for _, n := range res.Nodes {
			if keep != nil && !keep(n.Options.Name, n.Options.Type) {
				continue
			}
			if total >= maxProviderNodesTotal {
				notes = append(notes, "kat event=provider_node_skipped provider="+pc.Name+" reason=total_node_limit_"+strconv.Itoa(maxProviderNodesTotal))
				break
			}
			o := n.OutboundOptions()
			name := o.Name
			if taken[name] { // global conflict: name@provider, then #n
				orig := name
				name = provider.SuffixedName(orig, "@"+pc.Name)
				for i := 2; taken[name]; i++ {
					name = provider.SuffixedName(orig, "@"+pc.Name+"#"+strconv.Itoa(i))
				}
				notes = append(notes, "kat event=provider_node_renamed provider="+pc.Name+" from="+eventToken(orig, 128)+" to="+eventToken(name, 128))
			}
			taken[name] = true
			o.Name = name
			types[name] = o.Type
			outs = append(outs, OutboundConfig(o))
			byProvider[pc.Name] = append(byProvider[pc.Name], name)
			total++
		}
	}
	c.Outbounds = outs
	c.providerNodes = len(outs) - written
	groups := append([]GroupConfig(nil), c.Groups...)
	for i := range groups {
		g := &groups[i]
		explicit := append([]string(nil), g.Members...)
		def := g.Selected
		if def == "" && len(explicit) > 0 {
			def = explicit[0]
		}
		g.ConfigDefault, g.Expanded = def, true
		if g.Type == group.TypeRelay || !group.Options(*g).Dynamic() {
			continue
		}
		keep, _ := group.MemberFilter(group.Options(*g))
		in := map[string]bool{}
		for _, m := range explicit {
			in[m] = true
		}
		members := explicit
		addAll := func(names []string) {
			for _, n := range names {
				if in[n] || n == g.Name || len(members) >= 1024 {
					continue
				}
				if keep != nil && !keep(n, types[n]) {
					continue
				}
				in[n] = true
				members = append(members, n)
			}
		}
		if g.IncludeAll || g.IncludeAllProxies {
			var names []string
			for _, o := range c.Outbounds[:written] {
				names = append(names, o.Name)
			}
			addAll(names)
		}
		use := append([]string(nil), g.Use...)
		if g.IncludeAll || g.IncludeAllProviders {
			for _, pc := range c.Providers {
				use = append(use, pc.Name)
			}
		}
		seenUse := map[string]bool{}
		for _, u := range use {
			if !seenUse[u] {
				seenUse[u] = true
				addAll(byProvider[u])
			}
		}
		g.Members = members
		if g.Selected != "" && !in[g.Selected] {
			notes = append(notes, "kat event=group_selected_unavailable group="+eventToken(g.Name, 64)+" action=first_member")
			g.Selected = ""
		}
		if len(members) == 0 {
			notes = append(notes, "kat event=group_empty group="+eventToken(g.Name, 64)+" reason=no_provider_node")
		}
	}
	c.Groups = groups
	c.expanded = true
	return notes
}

// ProviderView is one entry of the planned "providers" section of GET /v1/stats.
type ProviderView struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Source   string    `json:"source"` // none | cache | fetch | file
	Format   string    `json:"format,omitempty"`
	Nodes    int       `json:"nodes"`
	Skipped  int       `json:"skipped"`
	Updated  time.Time `json:"updated,omitzero"`
	Attempt  time.Time `json:"last_attempt,omitzero"`
	Updates  int64     `json:"updates"`
	Failures int64     `json:"failures"`
	LastErr  string    `json:"last_error,omitempty"`
}

func (k *core) providerViews() []ProviderView {
	k.provMu.Lock()
	list := make([]*providerRT, 0, len(k.providers))
	for _, p := range k.providers {
		list = append(list, p)
	}
	k.provMu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].cfg.Name < list[j].cfg.Name })
	out := []ProviderView{}
	for _, p := range list {
		p.mu.Lock()
		out = append(out, ProviderView{Name: p.cfg.Name, Type: p.cfg.Type, Source: p.source, Format: p.res.Format, Nodes: len(p.res.Nodes), Skipped: len(p.res.Skipped),
			Updated: p.updated, Attempt: p.attempt, Updates: p.updates, Failures: p.failures, LastErr: p.lastErr})
		p.mu.Unlock()
	}
	return out
}

// ProviderReport is the kat check view of one provider.
type ProviderReport struct {
	Name         string
	Type         string
	Source       string // file | cache | none
	Format       string
	Nodes        []string
	Skipped      []provider.Skipped
	Renamed      [][2]string
	Ignored      []string // "node: field" accepted without effect
	Fingerprints []string // "node: client-fingerprint=X" (applied to TLS outbounds)
	Error        string
}

// GroupReport lists the members of one group after expansion.
type GroupReport struct {
	Name    string
	Type    string
	Members int
}

// CheckProviders loads every provider from its local source (file, or the
// http cache; kat check never uses the network), expands the groups and
// validates the resulting configuration.
func CheckProviders(c Config) ([]ProviderReport, []GroupReport, error) {
	if e := c.Validate(); e != nil {
		return nil, nil, e
	}
	provs := map[string]*providerRT{}
	var reps []ProviderReport
	sf := c.statsFile()
	for _, pc := range c.Providers {
		p := newProviderRT(nil, pc, sf)
		rep := ProviderReport{Name: pc.Name, Type: pc.Type, Source: "none"}
		if rejected, e := p.loadLocal(); e != nil {
			rep.Error = e.Error()
			rep.Format, rep.Skipped, rep.Renamed = rejected.Format, rejected.Skipped, rejected.Renamed
		} else if res, ok := p.snapshot(); ok {
			rep.Source, rep.Format, rep.Skipped, rep.Renamed = p.source, res.Format, res.Skipped, res.Renamed
			for _, n := range res.Nodes {
				rep.Nodes = append(rep.Nodes, n.Options.Name)
				for _, f := range n.Ignored {
					rep.Ignored = append(rep.Ignored, n.Options.Name+": "+f)
				}
				if n.ClientFingerprint != "" && (n.Options.Type == "trojan" || n.Options.Type == "anytls") {
					rep.Fingerprints = append(rep.Fingerprints, n.Options.Name+": client-fingerprint="+n.ClientFingerprint)
				}
			}
		} else if pc.Type == "http" {
			rep.Error = "no cache yet; kat check does not fetch"
		}
		provs[pc.Name] = p
		reps = append(reps, rep)
	}
	written := len(c.Outbounds)
	expandProviders(&c, provs)
	cursor := written
	for i, pc := range c.Providers {
		res, _ := provs[pc.Name].snapshot()
		keep, _ := providerFilter(pc)
		for _, n := range res.Nodes {
			if keep != nil && !keep(n.Options.Name, n.Options.Type) {
				continue
			}
			if cursor >= len(c.Outbounds) {
				break
			}
			name := c.Outbounds[cursor].Name
			cursor++
			if name != n.Options.Name {
				reps[i].Renamed = append(reps[i].Renamed, [2]string{n.Options.Name, name})
			}
		}
	}
	if e := c.Validate(); e != nil {
		return reps, nil, e
	}
	var groups []GroupReport
	for _, g := range c.Groups {
		groups = append(groups, GroupReport{g.Name, g.Type, len(g.Members)})
	}
	return reps, groups, nil
}
