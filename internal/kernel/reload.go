package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/api"
)

// ---- configuration generations ----
//
// A reload builds a complete new generation (routing, outbounds, groups, DNS,
// inbound codecs) and binds every needed listening socket before anything
// changes ("prepare"). Any failure discards the new generation and the
// sockets it opened; the running configuration is untouched. Only then the
// generation is installed in one step ("commit"): sockets whose address is
// unchanged are re-bound to the new generation without closing them, new
// sockets start accepting, removed ones stop accepting. Connections keep the
// generation that accepted them until they end; a generation is released
// (outbounds, groups, rule engine, DNS closed) when it is no longer current
// and its last connection or UDP association has ended.

// binding ties a listening socket to inbound idx of generation g.
type binding struct {
	g   *Server
	idx int
}

// tcpEntry is one listening TCP socket, kept across reloads while its
// address is configured.
type tcpEntry struct {
	key    string
	ln     net.Listener
	bind   atomic.Pointer[binding]
	xh     atomic.Pointer[xhttpRunner] // set while the bound inbound uses XHTTP
	closed atomic.Bool
	done   chan struct{}
	tfo    bool // TCP_FASTOPEN set on ln (reloadMu)
}

// listenKey normalizes a listen address so that equal addresses map to the
// same socket.
func listenKey(listen string) string {
	if ap, e := netip.ParseAddrPort(listen); e == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return listen
}

func ephemeralPort(key string) bool {
	_, port, e := net.SplitHostPort(key)
	return e == nil && port == "0"
}

// refEntry returns the generation bound to e with one reference taken, or
// nil when e no longer accepts.
func (k *core) refEntry(e *tcpEntry) (*Server, int, *xhttpRunner) {
	k.bindMu.RLock()
	defer k.bindMu.RUnlock()
	if e.closed.Load() {
		return nil, 0, nil
	}
	b := e.bind.Load()
	b.g.refs.Add(1) // current generation: refs >= 1 while bindMu is held
	return b.g, b.idx, e.xh.Load()
}

// tryRef takes a reference unless the generation is already released.
func (s *Server) tryRef() bool {
	for {
		n := s.refs.Load()
		if n <= 0 {
			return false
		}
		if s.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// unref drops one reference; the last one releases the generation.
func (s *Server) unref() {
	if s.core == nil {
		return
	}
	if s.refs.Add(-1) == 0 {
		s.release()
	}
}

// supersede marks the generation as no longer current: background work
// (group probing, rule-set refresh) stops and the "current" reference is
// dropped.
func (s *Server) supersede() {
	s.retireOnce.Do(func() {
		s.superseded.Store(true)
		if s.bgCancel != nil {
			s.bgCancel()
		}
		s.unref()
	})
}

func (s *Server) release() {
	s.rt.close()
	s.dns.close()
	s.gensMu.Lock()
	delete(s.gens, s.id)
	s.gensMu.Unlock()
	s.liveGens.Add(-1)
	s.notice(levelDebug, "kat event=config_generation_released generation="+strconv.FormatUint(s.id, 10))
}

// current returns the running generation.
func (s *Server) current() *Server {
	if s.core == nil {
		return s
	}
	if g := s.gen.Load(); g != nil {
		return g
	}
	return s
}

// CurrentConfig returns the configuration of the running generation.
func (s *Server) CurrentConfig() Config { return s.current().cfg }

// prepareError reports the stage at which a start or reload failed.
type prepareError struct {
	stage string
	err   error
}

func (e *prepareError) Error() string {
	if e.err == nil {
		return e.stage
	}
	return e.stage + ": " + e.err.Error()
}
func (e *prepareError) Unwrap() error { return e.err }

// plan holds what prepare created and commit installs (or abort undoes).
type plan struct {
	keys    []string
	newTCP  map[string]net.Listener
	newUDP  map[string]*ssUDPListener
	logger  *logger // non-nil: replace the log sink
	created []*xhttpRunner
	sel     map[string]selRecord
	selLog  []string
	tls     tlsPlan
	api     *api.Prepared
	state   *statePlan
}

func (p *plan) abort() {
	if p.api != nil {
		p.api.Abort()
	}
	if p.state != nil {
		p.state.abort()
	}
	for _, ln := range p.newTCP {
		ln.Close()
	}
	for _, u := range p.newUDP {
		u.socket.Close()
		u.releaseRcvBuf()
	}
	if p.logger != nil {
		p.logger.shutdown()
	}
}

// prepare builds generation c without changing the running state. The
// caller holds reloadMu (or is Start).
func (k *core) prepare(c Config, prev *Server) (*Server, *plan, error) {
	g := &Server{core: k, cfg: c, id: k.genSeq.Add(1)}
	g.refs.Store(1)
	l := c.Limits
	if prev != nil && prev.cfg.Limits.BufferSize == l.BufferSize && prev.cfg.Limits.PoolBuffers == l.PoolBuffers {
		g.pool = prev.pool
	} else {
		g.pool = newBufferPool(l.BufferSize, l.PoolBuffers)
	}
	p := &plan{newTCP: map[string]net.Listener{}, newUDP: map[string]*ssUDPListener{}}
	fail := func(stage string, e error) (*Server, *plan, error) {
		p.abort()
		g.rt.close()
		g.dns.close()
		return nil, nil, &prepareError{stage, e}
	}
	dns, e := newInternalDNS(c.DNS)
	if e != nil {
		return fail("dns", e)
	}
	g.dns = dns
	rt, e := g.buildRouting()
	if e != nil {
		return fail("routing", e)
	}
	g.rt = rt
	p.sel, p.selLog = k.applySelections(g)
	if e := g.prepareAnyTLS(prev); e != nil {
		return fail("inbound", e)
	}
	if e := g.prepareXHTTP(prev); e != nil {
		return fail("inbound", e)
	}
	if e := g.prepareVLESS(prev); e != nil {
		return fail("inbound", e)
	}
	if e := g.prepareEncrypted(prev); e != nil {
		return fail("inbound", e)
	}
	if e := g.prepareTLS(p); e != nil {
		return fail("tls", e)
	}
	seen := map[string]bool{}
	ephemeral := map[string]int{}
	for i := range g.cfg.Inbounds {
		in := &g.cfg.Inbounds[i]
		in.logIndex = i
		key := listenKey(in.Listen)
		if ephemeralPort(key) {
			// Port 0: every inbound gets its own socket; the n-th such
			// inbound of an address keeps its socket across reloads.
			n := ephemeral[key]
			ephemeral[key] = n + 1
			key += "#" + strconv.Itoa(n)
		}
		if seen[key] {
			return fail("bind_tcp", fmt.Errorf("inbound %d: listen %s is used twice", i, in.Listen))
		}
		seen[key] = true
		p.keys = append(p.keys, key)
		var addr net.Addr
		if e := k.tcpEntries[key]; e != nil {
			addr = e.ln.Addr()
		} else {
			ln, err := net.Listen("tcp", in.Listen)
			if err != nil {
				return fail("bind_tcp", fmt.Errorf("inbound %d: cannot listen on %s: %w", i, in.Listen, err))
			}
			p.newTCP[key] = ln
			addr = ln.Addr()
		}
		if in.ssRuntime != nil {
			k.udpMu.Lock()
			u := k.udpEntries[key]
			k.udpMu.Unlock()
			if u == nil {
				u, err := g.listenSSUDP(*in, addr)
				if err != nil {
					var rb *ssRcvBufError
					if errors.As(err, &rb) {
						p.abort()
						g.rt.close()
						g.dns.close()
						return nil, nil, err
					}
					return fail("bind_udp", fmt.Errorf("inbound %d: cannot listen on udp %s: %w", i, in.Listen, err))
				}
				u.key = key
				p.newUDP[key] = u
			}
		}
	}
	if prev != nil && logSinkChanged(prev.cfg.Log, c.Log) {
		lg, e := newLogger(c.Log)
		if e != nil {
			return fail("log", errors.New("cannot open log file"))
		}
		p.logger = lg
	}
	if prev != nil {
		p.api, e = k.prepareAPI(&c)
		if e != nil {
			return fail("api", e)
		}
		p.state, e = k.prepareState(&c, p.sel)
		if e != nil {
			return fail("stats", e)
		}
	}
	return g, p, nil
}

// logSinkChanged reports whether the log destination or format differ
// (level and access are applied in place).
func logSinkChanged(a, b *LogOptions) bool {
	var x, y LogOptions
	if a != nil {
		x = *a
	}
	if b != nil {
		y = *b
	}
	x.Level, y.Level, x.Access, y.Access = "", "", false, false
	return x != y
}

// commit installs prepared generation g. The caller holds reloadMu.
func (k *core) commit(g *Server, p *plan) error {
	// The last fallible operations happen before any generation/binding changes.
	if p.state != nil {
		if e := p.state.install(); e != nil {
			return &prepareError{"stats", e}
		}
	}

	prev := k.gen.Load()
	g.setupStats()
	ctx, cancel := context.WithCancel(k.ctx)
	g.bgCancel = cancel
	var starts []*tcpEntry
	var udpStarts []*ssUDPListener
	var drains []*ssUDPListener
	var removed []*tcpEntry
	var retire []*xhttpRunner
	udpUsed := map[string]bool{}
	k.bindMu.Lock()
	used := map[string]bool{}
	for i := range g.cfg.Inbounds {
		in := &g.cfg.Inbounds[i]
		key := p.keys[i]
		used[key] = true
		e := k.tcpEntries[key]
		if e == nil {
			e = &tcpEntry{key: key, ln: p.newTCP[key], done: make(chan struct{})}
			k.tcpEntries[key] = e
			starts = append(starts, e)
		}
		e.bind.Store(&binding{g, i})
		old := e.xh.Load()
		if in.xhttpServer != nil {
			if old != nil && old.codec == in.xhttpServer {
				old.bind.Store(&binding{g, i})
			} else {
				r := newXHTTPRunner(in.xhttpServer)
				r.bind.Store(&binding{g, i})
				e.xh.Store(r)
				p.created = append(p.created, r)
				if old != nil {
					retire = append(retire, old)
				}
			}
		} else if old != nil {
			e.xh.Store(nil)
			retire = append(retire, old)
		}
		g.listeners = append(g.listeners, e.ln)
		if in.ssRuntime != nil {
			udpUsed[key] = true
			k.udpMu.Lock()
			u := k.udpEntries[key]
			if u == nil {
				u = p.newUDP[key]
				k.udpEntries[key] = u
				udpStarts = append(udpStarts, u)
			}
			u.bind.Store(&udpBinding{g: g, idx: i, runtime: in.ssRuntime})
			u.draining.Store(false)
			k.udpMu.Unlock()
			g.ssListeners = append(g.ssListeners, u)
		}
	}
	for key, e := range k.tcpEntries {
		if !used[key] {
			e.closed.Store(true)
			delete(k.tcpEntries, key)
			removed = append(removed, e)
			if r := e.xh.Swap(nil); r != nil {
				retire = append(retire, r)
			}
		}
	}
	k.udpMu.Lock()
	for key, u := range k.udpEntries {
		if !udpUsed[key] && !u.draining.Load() {
			u.draining.Store(true)
			drains = append(drains, u)
		}
	}
	k.udpMu.Unlock()
	k.gen.Store(g)
	k.bindMu.Unlock()
	k.selMu.Lock()
	k.selections = p.sel
	k.selMu.Unlock()
	if len(p.selLog) > 0 {
		for _, line := range p.selLog {
			k.notice(levelInfo, line)
		}
		if p.state == nil {
			k.saveSelections()
		}
	}

	for _, e := range removed {
		e.ln.Close()
	}
	for _, r := range p.created {
		k.runners[r] = true
		k.accepts.Add(1)
		go k.runXHTTP(r)
	}
	for _, r := range retire {
		k.retireRunner(r)
	}
	for _, e := range starts {
		k.accepts.Add(1)
		go k.acceptLoop(e)
	}
	for _, u := range udpStarts {
		k.accepts.Add(1)
		go k.loopSSUDP(u)
	}
	for _, u := range drains {
		k.closeIfDrained(u)
	}
	k.applyTFO(g, p)
	k.commitTLS(g, p)
	k.checkTFO(&g.cfg)
	if prev != nil {
		k.applyRuntime(prev, g, p)
	}
	k.gensMu.Lock()
	if k.gens == nil {
		k.gens = map[uint64]*Server{}
	}
	k.gens[g.id] = g
	k.gensMu.Unlock()
	k.liveGens.Add(1)
	g.rt.start(ctx)
	if prev != nil {
		prev.supersede()
	}
	return nil
}

// applyRuntime switches the process-wide settings to those of g.
func (k *core) applyRuntime(prev, g *Server, p *plan) {
	l := g.cfg.Limits
	k.connSlots.setLimit(l.Connections)
	k.handSlots.setLimit(l.Handshakes)
	k.dialSlots.setLimit(l.Dials)
	k.udpSlots.setLimit(l.UDPAssociations)
	k.logicalSlots.setLimit(l.LogicalStreams)
	if p.logger != nil {
		k.log.replaceSink(p.logger)
	}
	k.log.access.Store(g.cfg.accessLog())
	if lv, pv := configuredLevel(g.cfg.Log), configuredLevel(prev.cfg.Log); lv != pv {
		k.log.setLevel(lv)
	}
	k.detailsOn.Store(g.cfg.connectionDetails())
	k.saveInterval.Store(int64(g.cfg.statsSaveInterval()))
	if p.state != nil {
		p.state.commit()
	}
	if p.api != nil {
		k.apiMu.Lock()
		k.api.srv = p.api.Commit()
		k.apiMu.Unlock()
	}
	k.guard.configure(&g.cfg)
}

func configuredLevel(o *LogOptions) logLevel {
	if o == nil {
		return levelInfo
	}
	lv, _ := parseLevel(o.Level)
	return lv
}

// ---- Reload ----

// ReloadResult is the outcome of one reload.
type ReloadResult struct {
	OK         bool      `json:"ok"`
	Generation uint64    `json:"generation,omitempty"`
	Stage      string    `json:"stage,omitempty"`
	Error      string    `json:"error,omitempty"`
	At         time.Time `json:"at"`
	DurationMS int64     `json:"duration_ms"`
	Trigger    string    `json:"trigger,omitempty"`
}

// ReloadError is returned by Reload when the new configuration was refused.
type ReloadError struct {
	Stage string
	Err   error
}

func (e *ReloadError) Error() string { return e.Stage + ": " + e.Err.Error() }

// SetConfigLoader sets the function that reads the configuration file again
// for Reload (the CLI passes the same loader it used at startup).
func (s *Server) SetConfigLoader(load func() (Config, error)) {
	s.reloadMu.Lock()
	s.loader = load
	s.reloadMu.Unlock()
}

// Reload reads the configuration again and installs it, or keeps the
// running configuration unchanged and returns a *ReloadError.
func (s *Server) Reload(trigger string) (ReloadResult, error) { return s.reload(trigger, true) }

func (s *Server) reload(trigger string, reread bool) (ReloadResult, error) {
	k := s.core
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	start := time.Now()
	res := ReloadResult{At: start, Trigger: trigger}
	failWith := func(stage string, e error) (ReloadResult, error) {
		res.Stage, res.Error, res.DurationMS = stage, e.Error(), time.Since(start).Milliseconds()
		k.reloadFailures.Add(1)
		k.lastReload.Store(&res)
		s.notice(levelWarn, "kat event=reload_failed trigger="+eventToken(trigger, 16)+" stage="+stage+" reason="+eventToken(e.Error(), 300))
		return res, &ReloadError{stage, e}
	}
	k.mu.Lock()
	closing := k.closing
	k.mu.Unlock()
	if closing {
		return failWith("closing", errors.New("server is shutting down"))
	}
	prev := k.gen.Load()
	var c Config
	var e error
	if reread {
		if k.loader == nil {
			return failWith("load", errors.New("reload is not available"))
		}
		c, e = k.loader()
	} else {
		// Never reuse prepared Config pointers or read a half-written user file.
		c, e = decodeConfig(prev.cfg.raw)
		if e == nil {
			if prev.cfg.defaults != [2]string{} {
				c.ApplyDefaultPaths(prev.cfg.defaults[0], prev.cfg.defaults[1])
			}
			if prev.cfg.stateDir != "" {
				c.ApplyDefaultStateDir(prev.cfg.stateDir)
			}
			for i := range c.Inbounds {
				if i < len(prev.cfg.Inbounds) && prev.cfg.Inbounds[i].ephemeralTLS {
					c.Inbounds[i].ephemeralTLS = true
					c.Inbounds[i].tlsConfig = prev.cfg.Inbounds[i].tlsConfig
				}
			}
		}
	}
	if e != nil {
		return failWith("load", e)
	}
	if e = c.Validate(); e != nil {
		return failWith("validate", e)
	}
	prov := k.syncProviders(&c, reread)
	prov.notes = append(prov.notes, expandProviders(&c, prov.next)...)
	if e = c.Validate(); e != nil {
		return failWith("validate", e)
	}
	g, p, e := k.prepare(c, prev)
	if e == nil {
		e = k.commit(g, p)
		if e != nil {
			p.abort()
			g.rt.close()
			g.dns.close()
		}
	}
	if e != nil {
		// The discarded generation does not consume a number (reloadMu is
		// held, so no other prepare runs): generations count installed
		// configurations.
		k.genSeq.Add(^uint64(0))
		stage := "prepare"
		var pe *prepareError
		if errors.As(e, &pe) {
			stage = pe.stage
			e = pe.err
		}
		return failWith(stage, e)
	}
	k.installProviders(prov)
	res.OK, res.Generation, res.DurationMS = true, g.id, time.Since(start).Milliseconds()
	k.reloads.Add(1)
	k.lastReload.Store(&res)
	s.notice(levelInfo, "kat event=reload_ok trigger="+eventToken(trigger, 16)+" generation="+strconv.FormatUint(g.id, 10)+" inbounds="+strconv.Itoa(len(g.cfg.Inbounds))+" duration_ms="+strconv.FormatInt(res.DurationMS, 10))
	return res, nil
}

// ReloadView is the reload section of GET /v1/stats.
type ReloadView struct {
	Generation      uint64        `json:"generation"`
	LiveGenerations int64         `json:"live_generations"`
	Reloads         int64         `json:"reloads"`
	Failures        int64         `json:"failures"`
	Last            *ReloadResult `json:"last,omitempty"`
	// Retained lists the superseded generations still held by connections
	// or UDP associations, with the number of references each one holds.
	Retained []RetainedGeneration `json:"retained"`
}

// RetainedGeneration is one superseded, not yet released generation.
type RetainedGeneration struct {
	Generation uint64 `json:"generation"`
	References int64  `json:"references"`
}

func (k *core) reloadView() ReloadView {
	v := ReloadView{LiveGenerations: k.liveGens.Load(), Reloads: k.reloads.Load(), Failures: k.reloadFailures.Load(), Last: k.lastReload.Load()}
	if g := k.gen.Load(); g != nil {
		v.Generation = g.id
	}
	v.Retained = []RetainedGeneration{}
	k.gensMu.Lock()
	for id, g := range k.gens {
		if id != v.Generation {
			v.Retained = append(v.Retained, RetainedGeneration{id, g.refs.Load()})
		}
	}
	k.gensMu.Unlock()
	sort.Slice(v.Retained, func(i, j int) bool { return v.Retained[i].Generation < v.Retained[j].Generation })
	return v
}

// ---- SS UDP sockets across generations ----

type udpBinding struct {
	g       *Server
	idx     int
	runtime *ssRuntime
}

// closeIfDrained closes a removed SS UDP socket once no association created
// on it is left. Until then it only serves existing associations.
func (k *core) closeIfDrained(u *ssUDPListener) {
	if !u.draining.Load() || u.assocs.Load() != 0 {
		return
	}
	k.udpMu.Lock()
	if u.draining.Load() && u.assocs.Load() == 0 && k.udpEntries[u.key] == u {
		delete(k.udpEntries, u.key)
		k.udpMu.Unlock()
		u.socket.Close()
		u.releaseRcvBuf()
		return
	}
	k.udpMu.Unlock()
}

// ---- XHTTP across generations ----

// xhttpRunner is one running XHTTP server fed with TLS connections by the
// accept loop of its socket. An unchanged XHTTP configuration keeps its
// runner (and its HTTP sessions) across reloads; a replaced runner keeps
// serving its open HTTP connections and stops when they are gone.
type xhttpRunner struct {
	codec  xhttpCodec
	ready  chan net.Conn
	closed chan struct{}
	once   sync.Once
	bind   atomic.Pointer[binding]
}

func newXHTTPRunner(codec xhttpCodec) *xhttpRunner {
	return &xhttpRunner{codec: codec, ready: make(chan net.Conn), closed: make(chan struct{})}
}

func (r *xhttpRunner) close() { r.once.Do(func() { close(r.closed) }) }

// ref returns the generation of r with one reference taken.
func (k *core) refRunner(r *xhttpRunner) (*Server, int) {
	k.bindMu.RLock()
	defer k.bindMu.RUnlock()
	b := r.bind.Load()
	if !b.g.tryRef() {
		return nil, 0
	}
	return b.g, b.idx
}

func (k *core) retireRunner(r *xhttpRunner) {
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-r.closed:
				return
			case <-k.ctx.Done():
				return
			case <-t.C:
				if r.codec.Stats().Connections == 0 {
					k.reloadMu.Lock()
					delete(k.runners, r)
					k.reloadMu.Unlock()
					r.close()
					return
				}
			}
		}
	}()
}
