package kernel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// proxySession is one association's datagram channel through one outbound or
// group. It is created on the first datagram routed there, read by exactly one
// goroutine, recycled after udp_idle without traffic in either direction and
// closed when the association ends.
type proxySession struct {
	name string
	pc   outbound.PacketConn
	last atomic.Int64 // unix nanos of the last datagram sent or received
}

func udpUnavailable(e error) bool {
	return errors.Is(e, outbound.ErrUDPUnsupported) || errors.Is(e, outbound.ErrNoMember)
}

// sendProxy forwards one datagram through the named outbound/group. Any
// failure drops only this datagram (counted and reported by fixed category).
func (a *udpAssociation) sendProxy(name string, dst Address, payload []byte) {
	s := a.server
	ses := a.proxySessionFor(name)
	if ses == nil {
		return
	}
	now := time.Now()
	ses.last.Store(now.UnixNano())
	ses.pc.SetWriteDeadline(now.Add(s.cfg.Limits.DialTimeout.value()))
	if _, e := ses.pc.WriteTo(payload, outbound.Addr{Host: dst.Host, Port: dst.Port}); e != nil {
		s.counters.Dropped.Add(1)
		switch {
		case udpUnavailable(e):
			s.failure(failOutboundUDP, "udp", -1)
		case !quietFailure(e):
			s.failure(failUDPIO, "udp", -1)
		}
		// A broken session (e.g. its UoT stream died) is replaced on the next datagram.
		a.dropProxy(ses)
		return
	}
	if !a.ssNative {
		a.activity.Store(time.Now().UnixNano())
	}
}

func (a *udpAssociation) proxySessionFor(name string) *proxySession {
	s := a.server
	a.mu.Lock()
	ses, closed, count := a.proxies[name], a.proxyClosed, len(a.proxies)
	a.mu.Unlock()
	if ses != nil {
		return ses
	}
	if closed || a.ctx.Err() != nil {
		s.counters.Dropped.Add(1)
		return nil
	}
	var ob outbound.Outbound
	if s.rt != nil {
		ob = s.rt.nodes[name]
	}
	if ob == nil || count >= s.rt.proxies {
		s.counters.Dropped.Add(1)
		s.failure(failUDPTargets, "udp", -1)
		return nil
	}
	if !ob.UDP() {
		s.counters.Dropped.Add(1)
		s.failure(failOutboundUDP, "udp", -1)
		return nil
	}
	l := s.cfg.Limits
	ctx, cancel := context.WithTimeout(a.ctx, l.DialTimeout.value()+l.HandshakeTimeout.value())
	pc, e := ob.ListenPacket(ctx)
	cancel()
	if e != nil {
		s.counters.Dropped.Add(1)
		switch {
		case udpUnavailable(e):
			s.failure(failOutboundUDP, "udp", -1)
		case errors.Is(e, outbound.ErrRejected):
			s.failure(failRoute, "outbound", -1)
		case a.ctx.Err() != nil:
		default:
			s.failure(failOutboundDial, "udp", -1)
		}
		return nil
	}
	ses = &proxySession{name: name, pc: pc}
	ses.last.Store(time.Now().UnixNano())
	a.mu.Lock()
	if a.proxyClosed {
		a.mu.Unlock()
		pc.Close()
		s.counters.Dropped.Add(1)
		return nil
	}
	if a.proxies == nil {
		a.proxies = map[string]*proxySession{}
	}
	a.proxies[name] = ses
	// The sender itself holds a wg count, so this Add never races a Wait at zero.
	a.wg.Add(1)
	a.mu.Unlock()
	go func() { defer a.wg.Done(); a.proxyReturnLoop(ses) }()
	return ses
}

// proxyReturnLoop delivers replies of one proxy session to the client via the
// association's normal output path. Replies come only from the session the
// association created, so each one renews both the session and the
// association (the same rule as an accepted direct reply).
func (a *udpAssociation) proxyReturnLoop(ses *proxySession) {
	defer a.dropProxy(ses)
	idle := a.server.cfg.Limits.UDPIdle.value()
	b := make([]byte, 65535)
	for {
		ses.pc.SetReadDeadline(time.Unix(0, ses.last.Load()).Add(idle))
		n, src, e := ses.pc.ReadFrom(b)
		if e != nil {
			var ne net.Error
			if (errors.Is(e, os.ErrDeadlineExceeded) || errors.As(e, &ne) && ne.Timeout()) && time.Since(time.Unix(0, ses.last.Load())) < idle && a.ctx.Err() == nil {
				continue
			}
			return
		}
		if n > maxDatagram {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		now := time.Now()
		ses.last.Store(now.UnixNano())
		if a.ssNative {
			a.touchSSActivity(now)
		} else {
			a.activity.Store(now.UnixNano())
		}
		host := src.Host
		if ip, e := netip.ParseAddr(host); e == nil {
			host = ip.WithZone("").Unmap().String()
		}
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if e = a.output(client, Address{host, src.Port}, b[:n], idle); e != nil {
			// Same as a direct reply write failure: the client side is gone.
			a.cancel()
			return
		}
	}
}

func (a *udpAssociation) dropProxy(ses *proxySession) {
	a.mu.Lock()
	if a.proxies[ses.name] == ses {
		delete(a.proxies, ses.name)
	}
	a.mu.Unlock()
	ses.pc.Close()
}

// closeProxies closes every proxy session and refuses new ones; their readers
// then exit and are joined through the association's wait group.
func (a *udpAssociation) closeProxies() {
	a.mu.Lock()
	a.proxyClosed = true
	list := a.proxies
	a.proxies = nil
	a.mu.Unlock()
	for _, ses := range list {
		ses.pc.Close()
	}
}
