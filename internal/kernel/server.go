package kernel

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/shui1iao/Kat/internal/route"
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
type Server struct {
	failures                                                     *failureLog
	events                                                       *eventLog
	rt                                                           *routingRuntime
	dns                                                          *internalDNS
	xhttpH1, xhttpH2, xhttpPacket, xhttpStreamUp, xhttpStreamOne atomic.Int64
	httpEarly                                                    atomic.Int64
	logicalSlots                                                 chan struct{}
	logical                                                      atomic.Int64
	cfg                                                          Config
	ctx                                                          context.Context
	cancel                                                       context.CancelFunc
	listeners                                                    []net.Listener
	ssListeners                                                  []*ssUDPListener
	nativeCancel                                                 context.CancelFunc
	nativeContext                                                context.Context
	mu                                                           sync.Mutex
	active                                                       map[net.Conn]*acceptedState
	closing                                                      bool
	wg                                                           sync.WaitGroup
	accepts                                                      sync.WaitGroup
	connSlots, handSlots, dialSlots, udpSlots                    chan struct{}
	pool                                                         *bufferPool
	counters                                                     Counters
	visionRead, visionWrite                                      atomic.Int64
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
func Start(c Config) (*Server, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := c.Limits
	s := &Server{cfg: c, ctx: ctx, cancel: cancel, active: map[net.Conn]*acceptedState{}, connSlots: make(chan struct{}, l.Connections), handSlots: make(chan struct{}, l.Handshakes), dialSlots: make(chan struct{}, l.Dials), udpSlots: make(chan struct{}, l.UDPAssociations), pool: newBufferPool(l.BufferSize, l.PoolBuffers)}
	s.failures = newFailureLog()
	s.logicalSlots = make(chan struct{}, l.LogicalStreams)
	var dnsErr error
	s.dns, dnsErr = newInternalDNS(c.DNS)
	if dnsErr != nil {
		s.failures.shutdown()
		cancel()
		return nil, dnsErr
	}
	s.events = &eventLog{write: s.failures.write}
	started := false
	defer func() {
		if !started {
			cancel()
			s.rt.close()
			s.events.shutdown()
			s.failures.shutdown()
			s.dns.close()
		}
	}()
	rt, e := s.buildRouting()
	if e != nil {
		return nil, errors.New("cannot build outbounds, groups or routing")
	}
	s.rt = rt
	s.nativeContext, s.nativeCancel = context.WithCancel(ctx)
	if e := s.prepareAnyTLS(); e != nil {
		cancel()
		return nil, e
	}
	if e := s.prepareXHTTP(); e != nil {
		cancel()
		return nil, e
	}
	if e := s.prepareVLESS(); e != nil {
		cancel()
		return nil, e
	}
	if e := s.prepareEncrypted(); e != nil {
		cancel()
		return nil, e
	}
	for i := range s.cfg.Inbounds {
		s.cfg.Inbounds[i].logIndex = i
		in := s.cfg.Inbounds[i]
		ln, e := net.Listen("tcp", in.Listen)
		if e != nil {
			for _, v := range s.listeners {
				v.Close()
			}
			for _, u := range s.ssListeners {
				u.socket.Close()
				u.releaseRcvBuf()
			}
			cancel()
			return nil, errors.New("cannot bind inbound listener")
		}
		s.listeners = append(s.listeners, ln)
		if in.ssRuntime != nil {
			u, e := s.listenSSUDP(in, ln.Addr())
			if e != nil {
				for _, v := range s.listeners {
					v.Close()
				}
				for _, v := range s.ssListeners {
					v.socket.Close()
					v.releaseRcvBuf()
				}
				cancel()
				var rb *ssRcvBufError
				if errors.As(e, &rb) {
					return nil, e
				}
				return nil, errors.New("cannot bind SS UDP listener")
			}
			s.ssListeners = append(s.ssListeners, u)
		}
	}
	for i, ln := range s.listeners {
		s.accepts.Add(1)
		if s.cfg.Inbounds[i].xhttpServer != nil {
			go s.serveXHTTP(ln, s.cfg.Inbounds[i])
		} else {
			go s.accept(ln, s.cfg.Inbounds[i])
		}
	}
	for _, u := range s.ssListeners {
		s.accepts.Add(1)
		go s.loopSSUDP(u)
	}
	started = true
	// Groups (probing) and the engine (remote refresh) run until Close.
	s.rt.start(ctx)
	return s, nil
}
func (s *Server) Addresses() []net.Addr {
	a := make([]net.Addr, len(s.listeners))
	for i, l := range s.listeners {
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
func (s *Server) accept(l net.Listener, in Inbound) {
	defer s.accepts.Done()
	delay := time.Duration(0)
	for {
		c, e := l.Accept()
		if e != nil {
			s.mu.Lock()
			closed := s.closing
			s.mu.Unlock()
			if closed {
				return
			}
			s.failure(failAccept, in.Protocol, in.logIndex)
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay = min(delay*2, time.Second)
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		if !acquire(s.connSlots) {
			s.failure(failConnections, in.Protocol, in.logIndex)
			s.counters.Rejected.Add(1)
			if in.ssRuntime != nil {
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			}
			c.Close()
			continue
		}
		if !acquire(s.handSlots) {
			s.failure(failHandshakes, in.Protocol, in.logIndex)
			<-s.connSlots
			s.counters.Rejected.Add(1)
			if in.ssRuntime != nil {
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			}
			c.Close()
			continue
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			<-s.connSlots
			<-s.handSlots
			if in.ssRuntime != nil {
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			}
			c.Close()
			return
		}
		s.active[c] = &acceptedState{ss: in.ssRuntime != nil, hand: true}
		s.wg.Add(1)
		s.mu.Unlock()
		s.counters.Accepted.Add(1)
		s.counters.Active.Add(1)
		s.counters.Handshakes.Add(1)
		go s.handle(c, in)
	}
}
func (s *Server) handle(raw net.Conn, in Inbound) {
	hand := true
	releaseHand := func() {
		if hand {
			hand = false
			s.mu.Lock()
			if state := s.active[raw]; state != nil {
				state.hand = false
			}
			s.mu.Unlock()
			<-s.handSlots
			s.counters.Handshakes.Add(-1)
		}
	}
	defer func() {
		releaseHand()
		raw.Close()
		s.mu.Lock()
		delete(s.active, raw)
		s.mu.Unlock()
		s.counters.Active.Add(-1)
		<-s.connSlots
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
	// The client address travels in the context for src_ip_cidr routing only.
	ctx := withSource(s.ctx, raw.RemoteAddr())
	if in.tlsConfig != nil {
		tc := tls.Server(raw, in.tlsConfig)
		if e := tc.HandshakeContext(s.ctx); e != nil {
			if !quietFailure(e) {
				s.failure(failTLS, in.Protocol, in.logIndex)
			}
			return
		}
		c = tc
	}
	if in.anytlsServer != nil {
		releaseHand()
		c.SetDeadline(time.Time{})
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
	if req.Command == 1 {
		out, e := s.dial(ctx, req.Target)
		if e != nil {
			req.respond(c, nil, false)
			return
		}
		defer out.Close()
		if e := req.respond(c, out.LocalAddr(), true); e != nil {
			if !quietFailure(e) {
				s.failure(failTCPIO, in.Protocol, in.logIndex)
			}
			return
		}
		if in.ssRuntime != nil && in.ssRuntime.v2022 {
			e = s.relaySS2022(s.ctx, c, ss2022DownTarget(in, out))
		} else {
			e = s.relay(s.ctx, c, ssDownTarget(in, out))
		}
	} else {
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
	select {
	case s.dialSlots <- struct{}{}:
	case <-ctx.Done():
		if s.ctx.Err() == nil {
			s.failure(failDialBudget, "outbound", -1)
		}
		return nil, ctx.Err()
	}
	s.counters.Dials.Add(1)
	defer func() { <-s.dialSlots; s.counters.Dials.Add(-1) }()
	if !s.networkPolicy() {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", a.String())
		s.outboundFailure(e)
		return c, e
	}
	d, host, e := s.decide(ctx, "tcp", a, sourceOf(parent))
	if e != nil {
		s.resolutionFailure(e)
		return nil, e
	}
	if d.Kind == route.Proxy {
		return s.dialProxy(parent, start, d.Outbound, host, a.Port)
	}
	for _, ip := range d.Candidates {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", netip.AddrPortFrom(ip, a.Port).String())
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	s.failure(failDial, "outbound", -1)
	return nil, errors.New("destination dial failed")
}

// Close stops admission, permits bounded draining, then forcibly cancels all streams.
// Concurrent calls are safe; callers should supply the desired overall drain deadline.
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	for _, l := range s.listeners {
		l.Close()
	}
	for _, u := range s.ssListeners {
		u.socket.Close()
	}
	s.nativeCancel()
	s.accepts.Wait()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	var result error
	select {
	case <-done:
	case <-ctx.Done():
		result = ctx.Err()
		s.cancel()
		s.mu.Lock()
		var toClose []net.Conn
		for c, state := range s.active {
			if state.ss && state.hand {
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
			}
			toClose = append(toClose, c)
		}
		s.mu.Unlock()
		for _, c := range toClose {
			c.Close()
		}
		<-done
	}
	// Sockets are closed and every reader/association has finished.
	for _, u := range s.ssListeners {
		u.releaseRcvBuf()
	}
	s.cancel()
	s.rt.close()
	s.events.shutdown()
	s.dns.close()
	s.failures.shutdown()
	return result
}
