package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/ss"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type ssAssociationID struct {
	source  netip.AddrPort
	session uint64
}
type ssRuntime struct {
	codec        *ss.Server
	v2022        bool
	mu           sync.Mutex // serializes authenticated migration and reply destination selection
	associations map[ssAssociationID]*ssNativeAssociation
}
type ssUDPListener struct {
	logIndex int
	socket   *net.UDPConn
	runtime  *ssRuntime
	// Explicit udp_rcvbuf_2017 only: read-back sizes and the bytes still charged
	// to the process extra socket budget (released exactly once, after close).
	rcvbufBefore, rcvbufActual int
	rcvbufInitial              int64
	rcvbufCharge               atomic.Int64
}

// releaseRcvBuf returns this listener's charge once; concurrent/duplicate calls are no-ops.
func (l *ssUDPListener) releaseRcvBuf() { returnSSRcvBuf(l.rcvbufCharge.Swap(0)) }

type ssNativeAssociation struct {
	a          *udpAssociation
	runtime    *ssRuntime
	id         ssAssociationID
	capability *ss.Packet
	listener   *ssUDPListener
}

func (s *Server) listenSSUDP(in Inbound, bound net.Addr) (*ssUDPListener, error) {
	a := bound.(*net.TCPAddr)
	// TCP wildcard selection may be dual-stack [::] for an IPv4 config.
	// Preserve the configured UDP family, but use TCP's actual port (also :0).
	host, _, e := net.SplitHostPort(in.Listen)
	if e != nil {
		return nil, e
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("invalid SS UDP listen IP")
	}
	network := "udp6"
	if ip.To4() != nil {
		network = "udp4"
	}
	u, e := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone})
	if e != nil {
		return nil, e
	}
	l := &ssUDPListener{socket: u, runtime: in.ssRuntime, logIndex: in.logIndex}
	if in.SS != nil && in.SS.UDPRcvBuf2017 != 0 {
		if in.ssRuntime.v2022 {
			u.Close()
			return nil, &ssRcvBufError{"only SS2017 UDP listeners are supported"}
		}
		before, actual, charge, e := setSS2017RcvBuf(u, in.SS.UDPRcvBuf2017)
		if e != nil {
			u.Close()
			return nil, e
		}
		l.rcvbufBefore, l.rcvbufActual, l.rcvbufInitial = before, actual, charge
		l.rcvbufCharge.Store(charge)
	}
	return l, nil
}

// The0.5.12 TCP path now needs32775B, not65528B, per owned wire.
// Fund at most7 extra65535B UDP receive buffers from that released process
// wire budget:16*32775+7*65535=983145 <= old16*65528=1048448.
// Exactly one extra fixed reader per SS listener (SS2017, and since 0.5.20 SS2022)
// enables authenticated crypto to run on a second CPU while the other reader polls.
// Both share this single process pool: no new buffers, packet goroutines, larger
// socket buffer, larger association queue, or per-connection cache.
const ss2017ExtraReadBuffers = 7

var ss2017ReadSlots = make(chan struct{}, ss2017ExtraReadBuffers)

func (s *Server) loopSSUDP(l *ssUDPListener) {
	defer s.accepts.Done()
	if runtime.GOMAXPROCS(0) > 1 {
		select {
		case ss2017ReadSlots <- struct{}{}:
			s.accepts.Add(1)
			go func() { defer s.accepts.Done(); defer func() { <-ss2017ReadSlots }(); s.readSSUDP(l) }()
		default:
		}
	}
	s.readSSUDP(l)
}
func (s *Server) readSSUDP(l *ssUDPListener) {
	wire := make([]byte, 65535)
	defer clear(wire)
	for {
		n, source, e := l.socket.ReadFromUDPAddrPort(wire)
		if e != nil {
			if !quietFailure(e) {
				s.failure(failUDPIO, "shadowsocks", l.logIndex)
			}
			return
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		if n > maxDatagram || !acquire(s.handSlots) {
			s.counters.Dropped.Add(1)
			if n > maxDatagram {
				s.failure(failUDPInvalid, "shadowsocks", l.logIndex)
			} else {
				s.failure(failUDPBudget, "shadowsocks", l.logIndex)
			}
			continue
		}
		rt := l.runtime
		// Header parsing and AEAD authentication run outside the routing lock for
		// both SS2017 and SIP022. The codec itself atomically checks+commits the
		// replay window, session creation and authenticated-peer migration under
		// its own mutex, only after authentication. Since 0.5.20 the SIP022
		// association capability/listener update below is no longer serialized
		// with that codec commit (approved trade-off: concurrent readers may
		// briefly leave an older listener selected after migration).
		p, e := rt.codec.DecodeUDP(wire[:n], source)
		<-s.handSlots
		if e != nil {
			s.counters.Dropped.Add(1)
			s.failure(failUDPInvalid, "shadowsocks", l.logIndex)
			continue
		}
		rt.mu.Lock()
		if s.nativeContext.Err() != nil {
			rt.mu.Unlock()
			s.counters.Dropped.Add(1)
			continue
		}
		id := ssAssociationID{source: source}
		if rt.v2022 {
			id = ssAssociationID{session: p.ClientSessionID}
		}
		assoc := rt.associations[id]
		if assoc != nil && (assoc.a.ctx.Err() != nil || assoc.a.ssIdleExpired(time.Now())) {
			assoc.a.cancel()
			delete(rt.associations, id)
			assoc = nil
		}
		if assoc == nil {
			if !acquire(s.udpSlots) {
				rt.mu.Unlock()
				s.counters.Dropped.Add(1)
				s.failure(failUDPBudget, "shadowsocks", l.logIndex)
				continue
			}
			ctx, cancel := context.WithCancel(s.nativeContext)
			a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, ssNative: true, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: map[netip.AddrPort]time.Time{}, source: source.Addr()}
			if e = a.openOutbound(); e != nil {
				cancel()
				<-s.udpSlots
				rt.mu.Unlock()
				s.counters.Dropped.Add(1)
				s.failure(failUDPIO, "shadowsocks", l.logIndex)
				continue
			}
			a.activity.Store(p.AuthenticatedAt().UnixNano())
			assoc = &ssNativeAssociation{a: a, runtime: rt, id: id}
			a.writeBack = assoc.reply
			rt.associations[id] = assoc
			s.counters.UDP.Add(1)
			s.wg.Add(1)
			go s.runSSAssociation(assoc)
		}
		assoc.capability = p
		assoc.listener = l
		// Only a fully authenticated, fresh, formatted request reaches here.
		assoc.a.touchSSActivity(p.AuthenticatedAt())
		assoc.a.enqueue(packet{Address{p.Target.Host, p.Target.Port}, p.Payload})
		rt.mu.Unlock()
	}
}
func (a *udpAssociation) openOutbound() error {
	var e error
	s := a.server
	a.outbound4, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv4)})
	if e != nil {
		return e
	}
	a.outbound6, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv6)})
	if e != nil && s.cfg.UDPBindIPv6 != "" {
		a.outbound4.Close()
		return e
	}
	a.activity.Store(time.Now().UnixNano())
	return nil
}
func (a *udpAssociation) closeOutbound() {
	a.outbound4.Close()
	if a.outbound6 != nil {
		a.outbound6.Close()
	}
}
func (s *Server) runSSAssociation(n *ssNativeAssociation) {
	a := n.a
	defer func() {
		a.cancel()
		a.closeOutbound()
		n.runtime.mu.Lock()
		if n.runtime.associations[n.id] == n {
			delete(n.runtime.associations, n.id)
		}
		n.runtime.mu.Unlock()
		for {
			select {
			case p := <-a.queue:
				a.queuedBytes.Add(-int64(len(p.payload)))
			default:
				s.counters.UDP.Add(-1)
				<-s.udpSlots
				s.wg.Done()
				return
			}
		}
	}()
	a.wg.Add(2)
	go func() { defer a.wg.Done(); <-a.ctx.Done(); a.closeOutbound() }()
	go func() { defer a.wg.Done(); defer a.cancel(); a.sendLoop() }()
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket != nil {
			a.wg.Add(1)
			go func() { defer a.wg.Done(); defer a.cancel(); a.returnLoop(socket) }()
		}
	}
	// The association and codec use configured bidirectional inactivity, not
	// the timestamp/replay retention interval. Return readers also enforce idle.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			a.wg.Wait()
			return
		case <-ticker.C:
			expired := a.ssIdleExpired(time.Now())
			if expired {
				a.cancel()
			}
		}
	}
}
func (n *ssNativeAssociation) reply(from Address, payload []byte) error {
	n.runtime.mu.Lock()
	if n.a.ctx.Err() != nil {
		n.runtime.mu.Unlock()
		return context.Canceled
	}
	capability, listener := n.capability, n.listener
	// Encode and socket I/O never hold the routing lock. SS2017 Packet.source is
	// immutable. For SIP022 (0.5.20) the codec still picks the latest
	// authenticated peer and response counter atomically under its own mutex;
	// only the listener snapshot may briefly lag a concurrent migration.
	n.runtime.mu.Unlock()
	wire, peer, e := n.runtime.codec.EncodeUDP(capability, ss.Address{Host: from.Host, Port: from.Port}, payload)
	if e != nil {
		return e
	}
	if len(wire) > maxDatagram {
		n.a.server.counters.Dropped.Add(1)
		return nil
	}
	// The authenticated codec, not the association's original source, chooses peer.
	l := listener
	if l == nil {
		return errors.New("missing authenticated SS listener")
	}
	l.socket.SetWriteDeadline(time.Now().Add(n.a.server.cfg.Limits.DialTimeout.value()))
	_, e = l.socket.WriteToUDPAddrPort(wire, peer)
	return e
}
