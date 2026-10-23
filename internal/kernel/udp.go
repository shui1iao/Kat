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
	select {
	case s.dialSlots <- struct{}{}:
	case <-ctx.Done():
		return netip.AddrPort{}, ctx.Err()
	}
	s.counters.Dials.Add(1)
	defer func() { <-s.dialSlots; s.counters.Dials.Add(-1) }()
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
	if !acquire(s.udpSlots) {
		_ = r.respond(c, nil, false)
		return errors.New("UDP association limit")
	}
	s.counters.UDP.Add(1)
	defer func() { <-s.udpSlots; s.counters.UDP.Add(-1) }()
	parent := s.ctx
	if r.Context != nil {
		parent = r.Context
	}
	ctx, cancel := context.WithCancel(parent)
	a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, stream: c, req: r, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: make(map[netip.AddrPort]time.Time)}
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
	}
}
func (a *udpAssociation) nativeLoop() error {
	b := make([]byte, 65535)
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
			continue
		}
		if n < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
			a.server.counters.Dropped.Add(1)
			continue
		}
		reader := bytes.NewReader(b[3:n])
		target, e := readAddress(reader, false)
		if e != nil || reader.Len() > maxDatagram || target.Port == 0 {
			a.server.counters.Dropped.Add(1)
			continue
		}
		a.mu.Lock()
		if a.client.Port() == 0 {
			a.client = src
		}
		a.mu.Unlock()
		payload := append([]byte(nil), b[n-reader.Len():n]...)
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
	for {
		select {
		case <-a.ctx.Done():
			return
		case p := <-a.queue:
			a.queuedBytes.Add(-int64(len(p.payload)))
			target, e := a.server.resolve(a.ctx, p.target)
			if e != nil {
				a.server.counters.Dropped.Add(1)
				continue
			}
			now := time.Now()
			a.mu.Lock()
			for k, t := range a.allowed {
				if now.Sub(t) > idle {
					delete(a.allowed, k)
				}
			}
			_, exists := a.allowed[target]
			if !exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets {
				a.mu.Unlock()
				a.server.counters.Dropped.Add(1)
				continue
			}
			a.allowed[target] = now
			a.mu.Unlock()
			socket := a.outbound4
			if target.Addr().Is6() {
				socket = a.outbound6
			}
			if socket == nil {
				a.server.counters.Dropped.Add(1)
				continue
			}
			socket.SetWriteDeadline(now.Add(a.server.cfg.Limits.DialTimeout.value()))
			if _, e = socket.WriteToUDPAddrPort(p.payload, target); e != nil {
				a.server.counters.Dropped.Add(1)
				continue
			}
			a.activity.Store(time.Now().UnixNano())
		}
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
		a.mu.Lock()
		last, ok := a.allowed[src]
		client := a.client
		a.mu.Unlock()
		if !ok || time.Since(last) > idle || n > maxDatagram {
			a.server.counters.Dropped.Add(1)
			continue
		}
		a.activity.Store(time.Now().UnixNano())
		payload := b[:n]
		source := Address{src.Addr().String(), src.Port()}
		a.outputMu.Lock()
		if a.writeBack != nil {
			e = a.writeBack(source, payload)
		} else if a.req.UDPWrite != nil {
			a.stream.SetWriteDeadline(time.Now().Add(idle))
			e = a.req.UDPWrite(source, payload)
		} else if a.native != nil {
			if client.Port() == 0 {
				a.outputMu.Unlock()
				continue
			}
			out := appendAddress([]byte{0, 0, 0}, source, false)
			out = append(out, payload...)
			if len(out) > maxDatagram {
				a.server.counters.Dropped.Add(1)
				a.outputMu.Unlock()
				continue
			}
			a.native.SetWriteDeadline(time.Now().Add(a.server.cfg.Limits.DialTimeout.value()))
			_, e = a.native.WriteToUDPAddrPort(out, client)
		} else {
			out := a.req.Datagrams.AppendPacket(nil, source, payload)
			a.stream.SetWriteDeadline(time.Now().Add(idle))
			e = writeAll(a.stream, out)
		}
		a.outputMu.Unlock()
		if e != nil {
			return
		}
	}
}

// Datagram-over-stream parsing always uses ReadFull, never TCP Read boundaries.
