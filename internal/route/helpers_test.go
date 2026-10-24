package route

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDNS struct {
	calls atomic.Int64
	ips   []netip.Addr
	err   error
}

func (f *fakeDNS) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	return f.ips, f.err
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

var errDNSFail = errors.New("dns failure")

type eventLog struct {
	mu  sync.Mutex
	evs [][]string
}

func (l *eventLog) sink(ev string, f ...string) {
	l.mu.Lock()
	l.evs = append(l.evs, append([]string{ev}, f...))
	l.mu.Unlock()
}

func (l *eventLog) all() [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.evs)
}

// count returns how many events match ev and (optionally) the given key/value pairs.
func (l *eventLog) count(ev string, kv ...string) int {
	n := 0
	for _, e := range l.all() {
		if e[0] != ev {
			continue
		}
		ok := true
		for i := 0; i+1 < len(kv); i += 2 {
			found := false
			for j := 1; j+1 < len(e); j += 2 {
				if e[j] == kv[i] && e[j+1] == kv[i+1] {
					found = true
				}
			}
			ok = ok && found
		}
		if ok {
			n++
		}
	}
	return n
}

func mustEngine(t *testing.T, o Options, ev *eventLog) *Engine {
	t.Helper()
	var sink func(string, ...string)
	if ev != nil {
		sink = ev.sink
	}
	e, err := NewEngine(o, nil, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func decideHost(t *testing.T, e *Engine, host string, port uint16, dns *fakeDNS) (Decision, error) {
	t.Helper()
	return e.Decide(context.Background(), Metadata{Network: "tcp", Host: host, Port: port}, dns.resolve)
}

func decideIP(t *testing.T, e *Engine, ip string, port uint16) Decision {
	t.Helper()
	d, err := e.Decide(context.Background(), Metadata{Network: "tcp", IP: netip.MustParseAddr(ip), Port: port}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
