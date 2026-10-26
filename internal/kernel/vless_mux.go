package kernel

import (
	"context"
	"errors"
	VX "github.com/shui1iao/Kat/internal/vlessx"
	"net"
	"net/netip"
	"sync"
	"time"
)

type muxAssociation struct {
	a    *udpAssociation
	mu   sync.Mutex
	last VX.Datagram
}

// Table lives inside one authenticated physical request; UUID+physical session
// and SessionID+Generation bind authority, never the caller supplied GlobalID.
func (s *Server) serveMux(parent context.Context, c net.Conn, uuid [16]byte) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	mux, e := VX.NewMux(c, min(s.cfg.Limits.UDPAssociations, 1024))
	if e != nil {
		return e
	}
	defer mux.Close()
	var workers sync.WaitGroup
	table := map[uint16]*muxAssociation{}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			mux.Close()
		case <-stop:
		}
	}()
	defer close(stop)
	defer func() {
		cancel()
		for _, n := range table {
			n.a.cancel()
		}
		workers.Wait()
	}()
	for {
		c.SetReadDeadline(time.Now().Add(s.cfg.Limits.UDPIdle.value()))
		d, e := mux.ReadDatagram()
		if e != nil {
			return e
		}
		for id, node := range table {
			if node.a.ctx.Err() != nil {
				delete(table, id)
			}
		}
		n := table[d.SessionID]
		if n != nil && (n.last.Generation != d.Generation || n.a.ctx.Err() != nil) {
			n.a.cancel()
			delete(table, d.SessionID)
			n = nil
		}
		if n == nil {
			if !s.udpSlots.try() {
				s.counters.Dropped.Add(1)
				continue
			}
			f, fctx := s.newFlow(ctx, "udp", Address{})
			child, stop := context.WithCancel(fctx)
			a := &udpAssociation{server: s, ctx: child, cancel: stop, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: map[netip.AddrPort]time.Time{}, source: sourceOf(parent), flow: f}
			if e = a.openOutbound(); e != nil {
				stop()
				f.end("udp_socket_failed")
				s.udpSlots.release()
				return e
			}
			n = &muxAssociation{a: a, last: d}
			table[d.SessionID] = n
			node := n
			a.writeBack = func(source Address, payload []byte) error {
				if len(payload) > 8192 {
					s.counters.Dropped.Add(1)
					return nil
				}
				node.mu.Lock()
				snapshot := node.last
				node.mu.Unlock()
				c.SetWriteDeadline(time.Now().Add(s.cfg.Limits.DialTimeout.value()))
				e := mux.Reply(snapshot, VX.Address{Host: source.Host, Port: source.Port}, payload)
				if errors.Is(e, VX.ErrState) {
					node.a.cancel()
				}
				return e
			}
			workers.Add(1)
			s.counters.UDP.Add(1)
			go func() {
				defer workers.Done()
				defer func() { s.counters.UDP.Add(-1); s.udpSlots.release(); a.flow.end("ok") }()
				s.runMuxUDP(a)
			}()
		}
		n.mu.Lock()
		n.last = d
		n.mu.Unlock()
		n.a.enqueue(packet{Address{d.Target.Host, d.Target.Port}, d.Payload})
	}
}
func (s *Server) runMuxUDP(a *udpAssociation) {
	defer a.closeOutbound()
	defer a.cancel()
	a.wg.Add(2)
	go func() { defer a.wg.Done(); <-a.ctx.Done(); a.closeOutbound() }()
	go func() { defer a.wg.Done(); defer a.cancel(); a.sendLoop() }()
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket != nil {
			a.wg.Add(1)
			go func() { defer a.wg.Done(); defer a.cancel(); a.returnLoop(socket) }()
		}
	}
	<-a.ctx.Done()
	a.wg.Wait()
	for {
		select {
		case p := <-a.queue:
			a.queuedBytes.Add(-int64(len(p.payload)))
		default:
			return
		}
	}
}
