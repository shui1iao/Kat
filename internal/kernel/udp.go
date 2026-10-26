package kernel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const maxDatagram = 65507

type packet struct {
	target  Address
	payload []byte
}
type udpAssociation struct {
	server                       *Server
	writeBack                    func(Address, []byte) error
	ssNative                     bool // only native SS uses bidirectional target idle refresh
	ctx                          context.Context
	cancel                       context.CancelFunc
	stream                       net.Conn
	outbound4, outbound6, native *net.UDPConn
	activity                     atomic.Int64
	queuedBytes                  atomic.Int64
	outputMu                     sync.Mutex
	req                          request
	queue                        chan packet
	mu                           sync.Mutex
	client                       netip.AddrPort
	allowed                      map[netip.AddrPort]time.Time
	wg                           sync.WaitGroup
	// Routing: client address (src_ip_cidr only, never logged) and the lazily
	// created per-outbound proxy sessions (guarded by mu).
	source      netip.Addr
	proxies     map[string]*proxySession
	proxyClosed bool
	// Statistics: the association's flow and the route of each direct
	// target (same lifetime as allowed, guarded by mu) for reply metering.
	flow   *flow
	routes map[netip.AddrPort]*udpRoute
	// Sniffing (0.7.0): with override_destination a direct reply from the
	// resolved address is reported from the client's original target.
	reverse map[netip.AddrPort]Address
}

func (s *Server) resolve(ctx context.Context, a Address) (netip.AddrPort, error) {
	if a.Port == 0 {
		return netip.AddrPort{}, errors.New("zero destination port")
	}
	if ip, e := netip.ParseAddr(a.Host); e == nil {
		return netip.AddrPortFrom(ip.Unmap(), a.Port), nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		return netip.AddrPort{}, e
	}
	s.counters.Dials.Add(1)
	defer func() { s.dialSlots.release(); s.counters.Dials.Add(-1) }()
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", a.Host)
	if e != nil {
		return netip.AddrPort{}, e
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, errors.New("no address")
	}
	return netip.AddrPortFrom(ips[0].Unmap(), a.Port), nil
}
func (s *Server) serveUDP(c net.Conn, r request) error {
	if !s.udpSlots.try() {
		s.failure(failUDPBudget, "udp", -1)
		_ = r.respond(c, nil, false)
		return errors.New("UDP association limit")
	}
	s.counters.UDP.Add(1)
	defer func() { s.udpSlots.release(); s.counters.UDP.Add(-1) }()
	parent := s.ctx
	if r.Context != nil {
		parent = r.Context
	}
	f, fparent := s.newFlow(parent, "udp", Address{})
	ctx, cancel := context.WithCancel(fparent)
	a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, stream: c, req: r, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: make(map[netip.AddrPort]time.Time), flow: f}
	a.source = sourceOf(parent)
	if !a.source.IsValid() {
		a.source = addrIP(c.RemoteAddr())
	}
	f.setSource(a.source)
	defer f.end("ok")
	defer cancel()
	var e error
	a.outbound4, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv4)})
	if e != nil {
		return e
	}
	defer a.outbound4.Close()
	a.outbound6, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv6)})
	if e != nil && s.cfg.UDPBindIPv6 != "" {
		return e
	}
	if a.outbound6 != nil {
		defer a.outbound6.Close()
	}
	if r.Mode == "socks5" {
		peer := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		ip, err := netip.ParseAddr(r.Target.Host)
		if err != nil {
			v, err := s.resolve(ctx, Address{r.Target.Host, 1})
			if err != nil {
				return err
			}
			ip = v.Addr()
		}
		if !ip.IsUnspecified() && ip.Unmap() != peer.Addr() {
			_ = r.respond(c, nil, false)
			return errors.New("UDP client address must match TCP peer")
		}
		a.client = netip.AddrPortFrom(peer.Addr(), r.Target.Port)
		local := c.LocalAddr().(*net.TCPAddr)
		a.native, e = net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
		if e != nil {
			return e
		}
		defer a.native.Close()
	}
	if r.Mode == "vless" && r.Target.Port == 0 {
		return errors.New("zero UDP destination")
	}
	var bound net.Addr
	if a.native != nil {
		bound = a.native.LocalAddr()
	}
	if e = r.respond(c, bound, true); e != nil {
		return e
	}
	a.activity.Store(time.Now().UnixNano())
	// One cancellation watcher, sender and return reader per association; never per packet.
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		<-ctx.Done()
		c.Close()
		a.outbound4.Close()
		if a.outbound6 != nil {
			a.outbound6.Close()
		}
		if a.native != nil {
			a.native.Close()
		}
	}()
	go func() { defer a.wg.Done(); defer cancel(); a.sendLoop() }()
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket == nil {
			continue
		}
		a.wg.Add(1)
		go func() { defer a.wg.Done(); defer cancel(); a.returnLoop(socket) }()
	}
	if a.native != nil {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); defer cancel(); var b [1]byte; _, _ = c.Read(b[:]) }()
		e = a.nativeLoop()
	} else {
		e = a.streamLoop()
	}
	cancel()
	a.wg.Wait()
	// Release all queued payloads; they are private bounded allocations, not shared pool references.
	for {
		select {
		case p := <-a.queue:
			a.queuedBytes.Add(-int64(len(p.payload)))
		default:
			return e
		}
	}
}
func (a *udpAssociation) enqueue(p packet) {
	n := int64(len(p.payload))
	limit := int64(a.server.cfg.Limits.UDPQueueBytes)
	// A zero limit only exists in isolated unit fixtures; validated servers always set it.
	if limit == 0 {
		limit = int64(a.server.cfg.Limits.UDPQueue * maxDatagram)
	}
	if a.ctx.Err() != nil {
		return
	}
	for {
		old := a.queuedBytes.Load()
		if n > limit-old {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPQueue, "udp", -1)
			return
		}
		if a.queuedBytes.CompareAndSwap(old, old+n) {
			break
		}
	}
	select {
	case <-a.ctx.Done():
		a.queuedBytes.Add(-n)
	case a.queue <- p:
	default:
		a.queuedBytes.Add(-n)
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPQueue, "udp", -1)
	}
}
func (a *udpAssociation) nativeLoop() error {
	b := make([]byte, 65535)
	var frags *reassembly // created by the first fragment (FRAG != 0)
	defer func() {
		if frags != nil {
			frags.close()
		}
	}()
	for {
		n, src, e := a.native.ReadFromUDPAddrPort(b)
		if e != nil {
			return e
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if src.Addr() != client.Addr() || (client.Port() != 0 && src.Port() != client.Port()) {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		if n < 4 || b[0] != 0 || b[1] != 0 {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		reader := bytes.NewReader(b[3:n])
		target, e := readAddress(reader, false)
		if e != nil || reader.Len() > maxDatagram || target.Port == 0 {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		a.mu.Lock()
		if a.client.Port() == 0 {
			a.client = src
		}
		a.mu.Unlock()
		payload := append([]byte(nil), b[n-reader.Len():n]...)
		if b[2] != 0 {
			if frags == nil {
				frags = a.newReassembly()
			}
			if frags == nil {
				a.server.frags.dropped.Add(1)
				continue
			}
			var ok bool
			if target, payload, ok = frags.add(b[2], target, payload); !ok {
				continue
			}
		}
		a.enqueue(packet{target, payload})
	}
}
func (a *udpAssociation) streamLoop() error {
	if a.req.UDPRead != nil {
		for {
			p, e := a.req.UDPRead()
			if e != nil {
				return e
			}
			a.enqueue(p)
		}
	}
	if a.req.Datagrams == nil {
		return errors.New("missing datagram codec")
	}
	for {
		p, e := a.req.Datagrams.ReadPacket(a.stream, a.req.Target)
		if e != nil {
			return e
		}
		a.enqueue(p)
	}
}
func (a *udpAssociation) sendLoop() {
	idle := a.server.cfg.Limits.UDPIdle.value()
	// Proxy sessions never outlive the association's sender.
	defer a.closeProxies()
	sn := a.newUDPSniffer()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-sn.timerC():
			sn.expire(a, time.Now(), idle)
		case p := <-a.queue:
			a.queuedBytes.Add(-int64(len(p.payload)))
			if sn != nil {
				sn.packet(a, p, idle)
				continue
			}
			a.send(a.ctx, p, idle)
		}
	}
}

// send routes and forwards one datagram (ctx may carry a sniff result).
func (a *udpAssociation) send(ctx context.Context, p packet, idle time.Duration) {
	candidates, proxy, host, rule, e := a.server.routeUDP(ctx, p.target, a.source)
	if e != nil {
		if errors.Is(e, errRouteReject) {
			a.flow.udpDecided(p.target, rule, []string{"reject"})
		}
		a.server.counters.Dropped.Add(1)
		a.server.resolutionFailure(e)
		return
	}
	overridden := sniffOf(ctx).target(p.target) != p.target
	if proxy != "" {
		dst := Address{host, p.target.Port}
		if overridden {
			// Replies through a proxy cannot be mapped back reliably:
			// the outbound gets the original target.
			dst = p.target
		}
		a.sendProxy(proxy, dst, p.payload, p.target, rule)
		return
	}
	var target netip.AddrPort
	var socket *net.UDPConn
	blocked := false
	for _, ip := range candidates {
		if a.server.cfg.blockedDestination(ip.Addr()) {
			blocked = true
			return
		}
		sock := a.outbound4
		if ip.Addr().Is6() {
			sock = a.outbound6
		}
		if sock != nil {
			target, socket = ip, sock
			break
		}
	}
	if socket == nil {
		a.server.counters.Dropped.Add(1)
		if blocked {
			a.server.failure(failBlocked, "udp", -1)
		} else {
			a.server.failure(failUDPInvalid, "udp", -1)
		}
		return
	}
	rt := a.flow.udpDecided(p.target, rule, []string{"direct"})
	now := time.Now()
	a.mu.Lock()
	for k, t := range a.allowed {
		if now.Sub(t) > idle {
			delete(a.allowed, k)
			delete(a.routes, k)
			delete(a.reverse, k)
		}
	}
	_, exists := a.allowed[target]
	if !exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets {
		a.mu.Unlock()
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPTargets, "udp", -1)
		return
	}
	a.allowed[target] = now
	if overridden {
		if a.reverse == nil {
			a.reverse = map[netip.AddrPort]Address{}
		}
		a.reverse[target] = p.target
	}
	if rt != nil {
		if a.routes == nil {
			a.routes = map[netip.AddrPort]*udpRoute{}
		}
		a.routes[target] = rt
	}
	a.mu.Unlock()
	socket.SetWriteDeadline(now.Add(a.server.cfg.Limits.DialTimeout.value()))
	if _, e = socket.WriteToUDPAddrPort(p.payload, target); e != nil {
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPIO, "udp", -1)
		return
	}
	a.flow.udpUp(rt, len(p.payload))
	if !a.ssNative {
		a.activity.Store(time.Now().UnixNano())
	}
}
func (a *udpAssociation) returnLoop(socket *net.UDPConn) {
	b := make([]byte, 65535)
	idle := a.server.cfg.Limits.UDPIdle.value()
	for {
		socket.SetReadDeadline(time.Unix(0, a.activity.Load()).Add(idle))
		n, src, e := socket.ReadFromUDPAddrPort(b)
		if e != nil {
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() && time.Since(time.Unix(0, a.activity.Load())) < idle {
				continue
			}
			return
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		now := time.Now()
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if !a.acceptReturn(src, n, now, idle) {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPSource, "udp", -1)
			continue
		}
		payload := b[:n]
		source := Address{src.Addr().String(), src.Port()}
		a.mu.Lock()
		if o, ok := a.reverse[src]; ok {
			source = o
		}
		a.mu.Unlock()
		if e = a.output(client, source, payload, idle); e != nil {
			return
		}
		if a.flow != nil {
			a.mu.Lock()
			rt := a.routes[src]
			a.mu.Unlock()
			a.flow.udpDown(rt, n)
		}
	}
}

// output writes one reply datagram back to the client through whichever
// inbound path owns this association (SS native writeBack, UDPWrite stream,
// SOCKS5 native socket or a datagram codec). Shared by direct and proxy replies.
func (a *udpAssociation) output(client netip.AddrPort, source Address, payload []byte, idle time.Duration) error {
	var e error
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	if a.writeBack != nil {
		e = a.writeBack(source, payload)
	} else if a.req.UDPWrite != nil {
		a.stream.SetWriteDeadline(time.Now().Add(idle))
		e = a.req.UDPWrite(source, payload)
	} else if a.native != nil {
		if client.Port() == 0 {
			return nil
		}
		out := appendAddress([]byte{0, 0, 0}, source, false)
		out = append(out, payload...)
		if len(out) > maxDatagram {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			return nil
		}
		a.native.SetWriteDeadline(time.Now().Add(a.server.cfg.Limits.DialTimeout.value()))
		_, e = a.native.WriteToUDPAddrPort(out, client)
	} else {
		out := a.req.Datagrams.AppendPacket(nil, source, payload)
		a.stream.SetWriteDeadline(time.Now().Add(idle))
		e = writeAll(a.stream, out)
	}
	return e
}

// Datagram-over-stream parsing always uses ReadFull, never TCP Read boundaries.

// ssIdleExpired uses the same last-valid-activity timestamp as target readers.
// It is SS-only: other protocols retain their existing idle/default behavior.
func (a *udpAssociation) ssIdleExpired(now time.Time) bool {
	return now.Sub(time.Unix(0, a.activity.Load())) >= a.server.cfg.Limits.UDPIdle.value()
}

// An exact target must already be authorized and not idle-expired BEFORE a reply
// can renew it. Unknown/expired sources and oversized datagrams never keep it alive.
// Refreshing only native SS preserves other protocol target-expiry semantics.
func (a *udpAssociation) acceptReturn(src netip.AddrPort, n int, now time.Time, idle time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, ok := a.allowed[src]
	expired := now.Sub(last) > idle
	if a.ssNative {
		expired = now.Sub(last) >= idle
	}
	if !ok || expired || n > maxDatagram {
		return false
	}
	if a.ssNative {
		if now.After(last) {
			a.allowed[src] = now
		}
		a.touchSSActivity(now)
	} else {
		a.activity.Store(now.UnixNano())
	}
	return true
}

// Concurrent SS readers/replies must not move the idle deadline backwards.
func (a *udpAssociation) touchSSActivity(now time.Time) {
	n := now.UnixNano()
	for old := a.activity.Load(); n > old; old = a.activity.Load() {
		if a.activity.CompareAndSwap(old, n) {
			return
		}
	}
}
