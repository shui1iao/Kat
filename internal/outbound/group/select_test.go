package group

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/shui1iao/Kat/internal/outbound"
)

func newSelect(t *testing.T, o Options, ms []outbound.Outbound, ev *eventLog) Group {
	t.Helper()
	o.Name, o.Type = "pick", TypeSelect
	o.Members = names(ms)
	var sink outbound.EventSink
	if ev != nil {
		sink = ev.sink
	}
	g, err := New(o, ms, sink)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSelectDefaultFirstMember(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	g := newSelect(t, Options{}, members(a, b), nil)
	if g.Current() != "a" {
		t.Fatalf("Current = %q, want a", g.Current())
	}
	if got := dial(t, g, "x.test"); got != "a" {
		t.Fatalf("dialed via %q, want a", got)
	}
	if g.Type() != "select" || g.Name() != "pick" {
		t.Fatalf("Name/Type = %q/%q", g.Name(), g.Type())
	}
}

func TestSelectSelectedOption(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	g := newSelect(t, Options{Selected: "b"}, members(a, b), nil)
	if g.Current() != "b" || dial(t, g, "x.test") != "b" {
		t.Fatalf("selected b not honored: current %q", g.Current())
	}
}

func TestSelectSwitchOnlyAffectsNewConnections(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	ev := &eventLog{}
	g := newSelect(t, Options{}, members(a, b), ev)
	old, err := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	peer := <-a.peers
	defer peer.Close()

	if err := g.(Selector).Select("b"); err != nil {
		t.Fatal(err)
	}
	if got := dial(t, g, "x.test"); got != "b" {
		t.Fatalf("new connection via %q, want b", got)
	}
	// The existing connection still runs over a.
	go func() { buf := make([]byte, 4); io.ReadFull(peer, buf); peer.Write([]byte("pong")) }()
	if _, err := old.Write([]byte("ping")); err != nil {
		t.Fatalf("old conn write after switch: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(old, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("old conn read after switch: %q %v", buf, err)
	}
	if ownerOf(old) != "a" {
		t.Fatalf("old conn owner %q", ownerOf(old))
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != "a>b" {
		t.Fatalf("switch events = %v", sw)
	}
	for _, e := range ev.all() {
		if len(e) != 7 || e[1] != "group" || e[2] != "pick" || e[3] != "from" || e[5] != "to" {
			t.Fatalf("event fields = %v (must be exactly group/from/to)", e)
		}
	}
}

func TestSelectUnknownNameError(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	g := newSelect(t, Options{Selected: "b"}, members(a, b), nil)
	if err := g.(Selector).Select("nope"); err == nil {
		t.Fatal("Select(nope) succeeded")
	}
	if g.Current() != "b" {
		t.Fatalf("failed Select changed current to %q", g.Current())
	}
	if _, ok := any(&autoGroup{}).(Selector); ok {
		t.Fatal("automatic groups must not implement Selector")
	}
}

func TestSelectDirectAndReject(t *testing.T) {
	direct := &loopOut{name: "direct"}
	rej := rejectOut{name: "reject"}
	a := newFake("a")
	g := newSelect(t, Options{Selected: "reject"}, members(a, direct, rej), nil)
	if _, err := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 80}); !errors.Is(err, outbound.ErrRejected) {
		t.Fatalf("select reject: err = %v, want ErrRejected", err)
	}
	if _, err := g.ListenPacket(context.Background()); !errors.Is(err, outbound.ErrRejected) {
		t.Fatalf("select reject UDP: err = %v, want ErrRejected", err)
	}
	if err := g.(Selector).Select("direct"); err != nil {
		t.Fatal(err)
	}
	if g.Current() != "direct" {
		t.Fatal("direct not selected")
	}
	// direct cannot do UDP here: the select group does not silently use another member.
	if _, err := g.ListenPacket(context.Background()); !errors.Is(err, outbound.ErrNoMember) {
		t.Fatalf("select direct UDP: err = %v, want ErrNoMember", err)
	}
	// select keeps the member's own conn type (no wrapping), e.g. *net.TCPConn for direct.
	ln := listenLoop(t)
	c, err := g.DialTCP(context.Background(), addrOf(ln))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(interface{ CloseWrite() error }); !ok {
		t.Fatalf("select returned %T, want the member's conn", c)
	}
}

func TestAutoGroupsRefuseReject(t *testing.T) {
	a := newFake("a")
	for _, typ := range []string{TypeURLTest, TypeFallback, TypeSmart} {
		// by name in Validate
		if err := Validate(Options{Name: "g", Type: typ, Members: []string{"a", "reject"}, Probe: probeOpts()}); err == nil {
			t.Fatalf("%s: Validate accepted reject", typ)
		}
		// by Type() in New
		_, err := New(Options{Name: "g", Type: typ, Members: []string{"a", "blk"}, Probe: probeOpts()},
			members(a, rejectOut{name: "blk"}), nil)
		if err == nil {
			t.Fatalf("%s: New accepted a reject-type member", typ)
		}
		// direct is fine
		g, err := New(Options{Name: "g", Type: typ, Members: []string{"a", "direct"}, Probe: probeOpts()},
			members(a, &loopOut{name: "direct"}), nil)
		if err != nil {
			t.Fatalf("%s with direct: %v", typ, err)
		}
		g.Close()
	}
}
