package group

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/shui1iao/Kat/internal/outbound"
)

// selectGroup uses exactly the selected member: no probing, no failover to
// other members (the user chose this path explicitly), no connection wrapping.
type selectGroup struct {
	cfg     config
	members []outbound.Outbound
	events  outbound.EventSink

	mu  sync.Mutex
	sel int
}

var _ Selector = (*selectGroup)(nil)

func (g *selectGroup) Name() string { return g.cfg.name }
func (g *selectGroup) Type() string { return g.cfg.kind }
func (g *selectGroup) Close() error { return nil }

func (g *selectGroup) Start(context.Context) {}

func (g *selectGroup) Members() []string { return append([]string(nil), g.cfg.members...) }

func (g *selectGroup) current() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sel
}

func (g *selectGroup) Current() string { return g.cfg.members[g.current()] }

// Select switches the member used by new connections and UDP sessions.
func (g *selectGroup) Select(name string) error {
	for i, m := range g.cfg.members {
		if m != name {
			continue
		}
		g.mu.Lock()
		old := g.sel
		g.sel = i
		g.mu.Unlock()
		if old != i {
			emitSwitch(g.events, g.cfg.name, g.cfg.members[old], name)
		}
		return nil
	}
	return fmt.Errorf("group %q: %q is not a member", g.cfg.name, name)
}

func (g *selectGroup) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	return g.members[g.current()].DialTCP(ctx, dst)
}

// ListenPacket uses the selected member only; when it cannot carry UDP the
// session fails with ErrNoMember instead of silently using another member.
func (g *selectGroup) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	m := g.members[g.current()]
	if !m.UDP() {
		return nil, noMember(g.cfg.name, "UDP")
	}
	return m.ListenPacket(ctx)
}

func (g *selectGroup) UDP() bool {
	for _, m := range g.members {
		if m.UDP() {
			return true
		}
	}
	return false
}

func (g *selectGroup) Snapshot() Snapshot {
	s := Snapshot{Name: g.cfg.name, Type: g.cfg.kind, Current: g.Current()}
	for i, m := range g.members {
		s.Members = append(s.Members, MemberSnapshot{Name: g.cfg.members[i], UDP: m.UDP()})
	}
	return s
}
