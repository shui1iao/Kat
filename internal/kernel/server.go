package kernel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/ss"
	"github.com/shui1iao/Kat/internal/stats"
	"github.com/shui1iao/Kat/internal/tlscert"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type TestDiagnostics struct {
	VisionReadDirect  int64 `json:"vision_read_direct"`
	VisionWriteDirect int64 `json:"vision_write_direct"`
	HTTPEarlyData     int64 `json:"http_early_data"`
	XHTTPH1           int64 `json:"xhttp_h1"`
	XHTTPH2           int64 `json:"xhttp_h2"`
	XHTTPPacket       int64 `json:"xhttp_packet_up"`
	XHTTPStreamUp     int64 `json:"xhttp_stream_up"`
	XHTTPStreamOne    int64 `json:"xhttp_stream_one"`
}

func (s *Server) Diagnostics() TestDiagnostics {
	return TestDiagnostics{VisionReadDirect: s.visionRead.Load(), VisionWriteDirect: s.visionWrite.Load(), HTTPEarlyData: s.httpEarly.Load(), XHTTPH1: s.xhttpH1.Load(), XHTTPH2: s.xhttpH2.Load(), XHTTPPacket: s.xhttpPacket.Load(), XHTTPStreamUp: s.xhttpStreamUp.Load(), XHTTPStreamOne: s.xhttpStreamOne.Load()}
}

type acceptedState struct{ ss, hand bool }

// core is the process-wide state shared by every configuration generation:
// budgets, connection registry, logging, statistics, management API and the
// inbound listening sockets. A reload replaces the generation, never the core.
type core struct {
	failures                                                     *failureLog
	events                                                       *eventLog
	xhttpH1, xhttpH2, xhttpPacket, xhttpStreamUp, xhttpStreamOne atomic.Int64
	httpEarly                                                    atomic.Int64
	logicalSlots                                                 *slots
	logical                                                      atomic.Int64
	ctx                                                          context.Context
	cancel                                                       context.CancelFunc
	nativeCancel                                                 context.CancelFunc
	nativeContext                                                context.Context
	mu                                                           sync.Mutex
	active                                                       map[net.Conn]*acceptedState
	closing                                                      bool
	wg                                                           sync.WaitGroup
	accepts                                                      sync.WaitGroup
	connSlots, handSlots, dialSlots, udpSlots                    *slots
	counters                                                     Counters
	visionRead, visionWrite                                      atomic.Int64

	// 0.7.0 runtime: log sink, statistics, connection registry, management API.
	log          *logger
	reg          *stats.Registry
	started      time.Time
	detailsOn    atomic.Bool
	flowID       atomic.Uint64
	flowMu       sync.Mutex
	flows        map[uint64]*flow
	tcpFlows     atomic.Int64
	api          *apiState
	apiMu        sync.Mutex // serializes API restarts
	statsMu      sync.Mutex // guards statsPath/statsRelease/lockedFile/selPath
	statsPath    string     // persisted statistics file ("" = not persisted)
	lockedFile   string     // statistics file whose instance lock is held
	statsRelease func()
	saveInterval atomic.Int64
	saveMu       sync.Mutex
	lastSave     atomic.Int64
	saveErrors   atomic.Int64
	bgStop       chan struct{}
	bgDone       chan struct{}
	stopOnce     sync.Once

	// 0.7.0 reload: generations and the listener registry.
	gen            atomic.Pointer[Server]
	genSeq         atomic.Uint64
	liveGens       atomic.Int64
	gensMu         sync.Mutex
	gens           map[uint64]*Server // live generations (current and retained)
	reloadMu       sync.Mutex         // serializes Reload, Select and Close's registry access
	bindMu         sync.RWMutex       // socket bindings: read per accepted connection, written by commit
	runners        map[*xhttpRunner]bool
	tcpEntries     map[string]*tcpEntry
	udpMu          sync.Mutex
	udpEntries     map[string]*ssUDPListener
	reloads        atomic.Int64
	reloadFailures atomic.Int64
	lastReload     atomic.Pointer[ReloadResult]
	loader         func() (Config, error)

	providers  map[string]*providerRT
	provMu     sync.Mutex
	rebuildCh  chan struct{}
	providerWG sync.WaitGroup

	// select groups: runtime choices (persisted next to the statistics file).
	selMu      sync.Mutex
	selections map[string]selRecord
	selPath    string

	// Server certificates and inbound protection are process-owned.
	tlsrt      tlsRuntime
	guard      *sourceGuard
	frags      fragmentPool
	bindActive atomic.Int64
	fallbacks  atomic.Int64
}

// Server is one configuration generation. Connections accepted while it is
// current keep using it (routing, outbounds, limits of that configuration)
// until they end; it is released when it is no longer current and its last
// connection has ended. The *Server returned by Start is the first
// generation; its exported methods always act on the running process.
type Server struct {
	*core
	rt          *routingRuntime
	dns         *internalDNS
	cfg         Config
	pool        *bufferPool
	keys        *statKeys
	listeners   []net.Listener
	ssListeners []*ssUDPListener
	byListen    map[string]int

	id         uint64
	refs       atomic.Int64 // live connections/associations; -1 once released
	superseded atomic.Bool
	bgCancel   context.CancelFunc
	retireOnce sync.Once
}
type Counters struct {
	Accepted   atomic.Int64
	Rejected   atomic.Int64
	Active     atomic.Int64
	Handshakes atomic.Int64
	Dials      atomic.Int64
	UDP        atomic.Int64
	Dropped    atomic.Int64
}
type Snapshot struct{ Accepted, Rejected, Active, Handshakes, Dials, UDP, Dropped int64 }

func (s *Server) Stats() Snapshot {
	c := &s.counters
	return Snapshot{c.Accepted.Load(), c.Rejected.Load(), c.Active.Load(), c.Handshakes.Load(), c.Dials.Load(), c.UDP.Load(), c.Dropped.Load()}
}

// newCore creates the shared state for configuration c (already validated).
func newCore(c *Config) (*core, error) {
	ctx, cancel := context.WithCancel(context.Background())
	l := c.Limits
	k := &core{ctx: ctx, cancel: cancel, active: map[net.Conn]*acceptedState{}, connSlots: newSlots(l.Connections), handSlots: newSlots(l.Handshakes), dialSlots: newSlots(l.Dials), udpSlots: newSlots(l.UDPAssociations), logicalSlots: newSlots(l.LogicalStreams)}
	lg, logErr := newLogger(c.Log)
	if logErr != nil {
		cancel()
		return nil, errors.New("cannot open log file")
	}
	k.log = lg
	k.failures = &failureLog{write: func(b []byte) error { return lg.emit(levelWarn, b) }, allow: func() bool { return lg.enabled(levelWarn) }}
	k.events = &eventLog{write: func(b []byte) error { return lg.emit(eventLevel(b), b) }, allow: func(event string) bool { return lg.enabled(eventLevelOf(event)) }}
	k.started = time.Now()
	k.detailsOn.Store(c.connectionDetails())
	k.flows = map[uint64]*flow{}
	k.reg = stats.New(nil, nil, nil, nil, k.started)
	k.nativeContext, k.nativeCancel = context.WithCancel(ctx)
	k.tcpEntries = map[string]*tcpEntry{}
	k.runners = map[*xhttpRunner]bool{}
	k.api = &apiState{}
	k.udpEntries = map[string]*ssUDPListener{}
	k.providers = map[string]*providerRT{}
	k.rebuildCh = make(chan struct{}, 1)
	k.selections = map[string]selRecord{}
	k.guard = newSourceGuard(k)
	return k, nil
}

// shutdownCore releases the shared sinks after a failed Start.
func (k *core) shutdownCore() {
	k.cancel()
	k.events.shutdown()
	k.failures.shutdown()
	k.releaseStatsLock()
	k.log.shutdown()
}

func Start(c Config) (*Server, error) {
	// Embedders have no Load bytes: capture the unprepared configuration too.
	if len(c.raw) == 0 {
		b, e := json.Marshal(c)
		if e != nil {
			return nil, e
		}
		c.raw = b
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	k, e := newCore(&c)
	if e != nil {
		return nil, e
	}
	// Statistics and select state are loaded before the first generation so
	// that persisted selections apply to it.
	k.openState(&c)
	k.reloadMu.Lock()
	prov := k.syncProviders(&c, true)
	prov.notes = append(prov.notes, expandProviders(&c, prov.next)...)
	if e := c.Validate(); e != nil {
		k.reloadMu.Unlock()
		k.shutdownCore()
		return nil, e
	}
	s, plan, e := k.prepare(c, nil)
	if e != nil {
		k.reloadMu.Unlock()
		k.shutdownCore()
		return nil, startError(e)
	}
	k.commit(s, plan)
	k.installProviders(prov)
	k.providerWG.Add(1)
	go func() { defer k.providerWG.Done(); k.rebuildLoop() }()
	k.reloadMu.Unlock()
	k.startStats(&c)
	k.startAPI(&c)
	return s, nil
}

// startError maps a preparation error to the 0.6.x startup errors.
func startError(e error) error {
	var rb *ssRcvBufError
	var pe *prepareError
	switch {
	case errors.As(e, &rb):
		return e
	case errors.As(e, &pe):
		switch pe.stage {
		case "bind_tcp":
			return errors.New("cannot bind inbound listener")
		case "bind_udp":
			return errors.New("cannot bind SS UDP listener")
		case "routing":
			return errors.New("cannot build outbounds, groups or routing")
		}
		if pe.err != nil {
			return pe.err
		}
	}
	return e
}

// Addresses returns the TCP listening addresses of the current configuration,
// in inbound order.
func (s *Server) Addresses() []net.Addr {
	cur := s.current()
	a := make([]net.Addr, len(cur.listeners))
	for i, l := range cur.listeners {
		a[i] = l.Addr()
	}
	return a
}
func acquire(ch chan struct{}) bool {
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// acceptLoop serves one listening TCP socket across generations: every
// accepted connection is handled by the generation bound to the socket at
// that moment.
func (k *core) acceptLoop(e *tcpEntry) {
	defer k.accepts.Done()
	defer close(e.done)
	l := e.ln
	delay := time.Duration(0)
	for {
		c, err := l.Accept()
		if err != nil {
			k.mu.Lock()
			closed := k.closing
			k.mu.Unlock()
			if closed || e.closed.Load() {
				return
			}
			b := e.bind.Load()
			b.g.failure(failAccept, b.g.cfg.Inbounds[b.idx].Protocol, b.idx)
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay = min(delay*2, time.Second)
			}
			select {
			case <-k.ctx.Done():
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		g, idx, xr := k.refEntry(e)
		if g == nil {
			c.Close()
			continue
		}
		if !g.screen(c, &g.cfg.Inbounds[idx]) {
			g.unref()
			continue
		}
		if xr != nil {
			in := &g.cfg.Inbounds[idx]
			cfg, timeout := in.tlsConfig, g.cfg.Limits.HandshakeTimeout.value()
			g.unref()
			k.acceptXHTTP(c, xr, cfg, timeout)
			continue
		}
		in := g.cfg.Inbounds[idx]
		if !g.admit(c, in) {
			k.guard.releaseConn(addrIP(c.RemoteAddr()))
			g.unref()
			continue
		}
		go g.handle(c, in)
	}
}

// admit applies the connection and handshake budgets and registers c.
// On false the connection has been closed.
func (s *Server) admit(c net.Conn, in Inbound) bool {
	refuse := func() {
		if in.ssRuntime != nil {
			if tcp, ok := c.(*net.TCPConn); ok {
				tcp.SetLinger(0)
			}
		}
		c.Close()
	}
	if !s.connSlots.try() {
		s.failure(failConnections, in.Protocol, in.logIndex)
		s.counters.Rejected.Add(1)
		refuse()
		return false
	}
	if !s.handSlots.try() {
		s.failure(failHandshakes, in.Protocol, in.logIndex)
		s.connSlots.release()
		s.counters.Rejected.Add(1)
		refuse()
		return false
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.connSlots.release()
		s.handSlots.release()
		refuse()
		return false
	}
	s.active[c] = &acceptedState{ss: in.ssRuntime != nil, hand: true}
	s.wg.Add(1)
	s.mu.Unlock()
	s.counters.Accepted.Add(1)
	s.counters.Active.Add(1)
	s.counters.Handshakes.Add(1)
	return true
}
func (s *Server) handle(raw net.Conn, in Inbound) {
	hand := true
	pinned := true // the connection holds a reference on s
	releaseHand := func() {
		if hand {
			hand = false
			s.mu.Lock()
			if state := s.active[raw]; state != nil {
				state.hand = false
			}
			s.mu.Unlock()
			s.handSlots.release()
			s.counters.Handshakes.Add(-1)
		}
	}
	defer func() {
		releaseHand()
		raw.Close()
		s.mu.Lock()
		delete(s.active, raw)
		s.mu.Unlock()
		s.guard.releaseConn(addrIP(raw.RemoteAddr()))
		s.counters.Active.Add(-1)
		s.connSlots.release()
		if pinned {
			s.unref()
		}
		s.wg.Done()
	}()
	raw.SetDeadline(time.Now().Add(s.cfg.Limits.HandshakeTimeout.value()))
	if in.Protocol == "vless" {
		s.handleVLESS(raw, in, releaseHand)
		return
	}
	if in.Protocol == "snell" {
		s.handleSnell(raw, in, releaseHand)
		return
	}
	var c net.Conn = raw
	// The client address travels in the context for src_ip_cidr routing and,
	// truncated, for the optional details/access log; the inbound index marks
	// client traffic for statistics and the destination guard.
	ctx := withInboundMeta(withInbound(withSource(s.ctx, raw.RemoteAddr()), in.logIndex), &in, raw.LocalAddr(), raw.RemoteAddr())
	if in.tlsConfig != nil {
		tc := tls.Server(raw, in.tlsConfig)
		if e := tc.HandshakeContext(s.ctx); e != nil {
			if !quietFailure(e) {
				s.failure(failTLS, in.Protocol, in.logIndex)
			}
			return
		}
		if tc.ConnectionState().NegotiatedProtocol == tlscert.ALPNProto {
			return // TLS-ALPN-01 validation: the handshake was the whole exchange
		}
		c = tc
	}
	if in.anytlsServer != nil {
		releaseHand()
		c.SetDeadline(time.Time{})
		// An AnyTLS session is a long-lived multiplexed carrier (clients pool
		// them); every stream takes its own reference on the generation that
		// routes it, so the session itself must not pin the accepting one.
		// Only the inbound codec and statistics keys of s are used after this,
		// and neither is closed by a release.
		pinned = false
		s.unref()
		s.serveAnyTLS(ctx, c, in)
		return
	}
	var req request
	var e error
	if in.ssRuntime != nil {
		req, e = s.acceptSS(raw, in)
	} else {
		req, e = adapters[in.Protocol](c, in)
	}
	if e != nil {
		var tr *trojanReject
		trojan := errors.As(e, &tr)
		if trojan && tr.auth || errors.Is(e, errSOCKSAuth) || errors.Is(e, ss.ErrAuth) {
			s.authFailed(raw.RemoteAddr(), &in)
		}
		if trojan && in.Fallback != "" {
			releaseHand()
			s.trojanFallback(c, tr.head, &in)
			return
		}
		if !quietFailure(e) {
			s.failure(failHandshake, in.Protocol, in.logIndex)
		}
		return
	}
	releaseHand()
	if req.Stream != nil {
		c = req.Stream
	}
	c.SetDeadline(time.Time{})
	if req.Command == 2 {
		if e := s.serveBind(ctx, c, req, &in); !quietFailure(e) {
			s.failure(failTCPIO, in.Protocol, in.logIndex)
		}
		return
	}
	if req.Command == 1 {
		// Sniffing (0.7.0): a SOCKS5 client waits for the reply before it
		// sends data, so it is answered first on sniffed ports.
		var early func() error
		if req.Mode == "socks5" {
			cc := c
			early = func() error { return req.respond(cc, nil, true) }
		}
		sctx, sc, first, responded, e := s.sniffTCP(ctx, c, req.Target, early)
		if e != nil {
			return
		}
		c = sc
		f, fctx := s.newFlow(sctx, "tcp", req.Target)
		out, e := s.dial(fctx, req.Target)
		if e != nil {
			f.end(dialResult(e))
			if !responded {
				req.respond(c, nil, false)
			}
			return
		}
		defer f.end("ok")
		defer out.Close()
		if !responded {
			if e := req.respond(c, out.LocalAddr(), true); e != nil {
				if !quietFailure(e) {
					s.failure(failTCPIO, in.Protocol, in.logIndex)
				}
				return
			}
		}
		if e := forwardSniffed(fctx, out, first); e != nil {
			return
		}
		// fctx is s.ctx plus values (and, with details, a per-connection cancel).
		if in.ssRuntime != nil && in.ssRuntime.v2022 {
			e = s.relaySS2022(fctx, c, ss2022DownTarget(in, out))
		} else {
			e = s.relay(fctx, c, ssDownTarget(in, out))
		}
	} else {
		if req.Context == nil {
			req.Context = ctx
		}
		e = s.serveUDP(c, req)
	}
	if !quietFailure(e) {
		if req.Command == 1 {
			s.failure(failTCPIO, in.Protocol, in.logIndex)
		} else {
			s.failure(failUDPIO, in.Protocol, in.logIndex)
		}
	}
}
func (s *Server) dial(ctx context.Context, a Address) (net.Conn, error) {
	start, parent := time.Now(), ctx
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if a.Port == 0 {
		return nil, errors.New("zero destination port")
	}
	if e := s.dialSlots.acquire(ctx); e != nil {
		if s.ctx.Err() == nil {
			s.failure(failDialBudget, "outbound", -1)
		}
		return nil, e
	}
	s.counters.Dials.Add(1)
	defer func() { s.dialSlots.release(); s.counters.Dials.Add(-1) }()
	f := flowOf(parent)
	// override_destination: an IP target becomes the sniffed domain.
	a = sniffOf(parent).target(a)
	if !s.networkPolicy() {
		f.route(0, []string{"direct"})
		c, e := s.directDialer().DialContext(ctx, "tcp", a.String())
		if blockedError(e) {
			s.failure(failBlocked, "outbound", -1)
			return nil, errBlocked
		}
		s.outboundFailure(e)
		return c, e
	}
	d, host, e := s.decide(ctx, "tcp", a, sourceOf(parent))
	if e == nil || errors.Is(e, errRouteReject) {
		f.route(d.Rule, []string{decisionHead(d)})
	}
	if e != nil {
		s.resolutionFailure(e)
		return nil, e
	}
	if d.Kind == route.Proxy {
		return s.dialProxy(parent, start, d.Outbound, host, a.Port)
	}
	blocked := 0
	for _, ip := range d.Candidates {
		if s.cfg.blockedDestination(ip) {
			blocked++
			continue
		}
		c, e := s.plainDialer().DialContext(ctx, "tcp", netip.AddrPortFrom(ip, a.Port).String())
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if blocked == len(d.Candidates) {
		s.failure(failBlocked, "outbound", -1)
		return nil, errBlocked
	}
	s.failure(failDial, "outbound", -1)
	return nil, errors.New("destination dial failed")
}

// decisionHead is the first element of the outbound chain of a decision.
func decisionHead(d route.Decision) string {
	switch d.Kind {
	case route.Proxy:
		return d.Outbound
	case route.Reject:
		return "reject"
	}
	return "direct"
}

// dialResult classifies a dial error for the access log.
func dialResult(e error) string {
	var dns *net.DNSError
	switch {
	case blockedError(e):
		return "blocked"
	case errors.Is(e, errRouteReject), errors.Is(e, outbound.ErrRejected):
		return "rejected"
	case errors.Is(e, errDNS), errors.As(e, &dns):
		return "dns_failed"
	case errors.Is(e, context.Canceled):
		return "canceled"
	}
	return "dial_failed"
}

// Close stops admission, permits bounded draining, then forcibly cancels all streams.
// Concurrent calls are safe; callers should supply the desired overall drain deadline.
func (s *Server) Close(ctx context.Context) error {
	k := s.core
	k.reloadMu.Lock()
	k.mu.Lock()
	k.closing = true
	k.mu.Unlock()
	k.guard.close()
	k.apiMu.Lock()
	k.api.close()
	k.apiMu.Unlock()
	for _, e := range k.tcpEntries {
		e.closed.Store(true)
		e.ln.Close()
	}
	k.udpMu.Lock()
	udps := make([]*ssUDPListener, 0, len(k.udpEntries))
	for _, u := range k.udpEntries {
		udps = append(udps, u)
		u.socket.Close()
	}
	k.udpMu.Unlock()
	for r := range k.runners {
		r.close()
	}
	k.reloadMu.Unlock()
	k.stopProviders()
	k.nativeCancel()
	k.accepts.Wait()
	done := make(chan struct{})
	go func() { k.wg.Wait(); close(done) }()
	var result error
	select {
	case <-done:
	case <-ctx.Done():
		result = ctx.Err()
		k.cancel()
		k.mu.Lock()
		var toClose []net.Conn
		for c, state := range k.active {
			if state.ss && state.hand {
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			}
			toClose = append(toClose, c)
		}
		k.mu.Unlock()
		for _, c := range toClose {
			c.Close()
		}
		<-done
	}
	// Sockets are closed and every reader/association has finished.
	for _, u := range udps {
		u.releaseRcvBuf()
	}
	k.cancel()
	k.providerWG.Wait()
	// Every connection has ended: the current generation is the last one.
	if cur := k.gen.Load(); cur != nil {
		cur.supersede()
	}
	k.events.shutdown()
	k.failures.shutdown()
	// Every flow has ended: the final save sees all transferred bytes.
	k.stopStats()
	k.log.shutdown()
	return result
}
