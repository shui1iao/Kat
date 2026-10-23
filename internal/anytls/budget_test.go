package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gatedTransport struct {
	net.Conn
	blocked atomic.Bool
	stop    chan struct{}
	once    sync.Once
}

func (g *gatedTransport) Write(p []byte) (int, error) {
	if g.blocked.Load() {
		<-g.stop
		return 0, io.ErrClosedPipe
	}
	return g.Conn.Write(p)
}
func (g *gatedTransport) Close() error { g.once.Do(func() { close(g.stop) }); return g.Conn.Close() }
func TestOutboundCountByteBudgetAndTimeoutCleanup(t *testing.T) {
	c := cfg()
	c.SessionOutboundFrames = 2
	c.SessionOutboundBytes = 150
	c.StreamOutboundFrames = 1
	c.StreamOutboundBytes = 80
	c.WriteTimeout = 80 * time.Millisecond
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	g := &gatedTransport{Conn: a, stop: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer b.Close()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	streams := make(chan *Stream, 4)
	begin := make(chan struct{})
	result := make(chan error, 1)
	writes := make(chan error, 4)
	go func() {
		result <- s.Serve(ctx, g, func(ctx context.Context, st *Stream, r Request) {
			streams <- st
			select {
			case <-begin:
			case <-ctx.Done():
				return
			}
			_, e := st.Write(make([]byte, 64))
			writes <- e
		})
	}()
	// Read all server controls while setting up streams.
	controls := make(chan testFrame, 16)
	go func() {
		defer close(controls)
		for {
			var h [7]byte
			if _, e := io.ReadFull(b, h[:]); e != nil {
				return
			}
			p := make([]byte, int(h[5])<<8|int(h[6]))
			if _, e := io.ReadFull(b, p); e != nil {
				return
			}
			controls <- testFrame{cmd: h[0], data: p}
		}
	}()
	f := fixtures(t)
	if e = writeAll(b, append(f["auth"], f["settings_v2"]...)); e != nil {
		t.Fatal(e)
	}
	<-controls
	var st *Stream
	for i := uint32(1); i <= 4; i++ {
		if e = writeAll(b, wire(cmdSYN, i, nil)); e != nil {
			t.Fatal(e)
		}
		<-controls
		if e = writeAll(b, wire(cmdPSH, i, targetBytes(t, Address{"x", 80}))); e != nil {
			t.Fatal(e)
		}
		st = <-streams
	}
	g.blocked.Store(true)
	close(begin)
	time.Sleep(15 * time.Millisecond)
	stats := st.SessionStats()
	if stats.OutboundFrames > 2 || stats.OutboundBytes > 150 || stats.OutboundFrames == 0 {
		t.Fatal(stats)
	}
	if e = <-result; !errors.Is(e, ErrWriteTimeout) {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		if e := <-writes; e == nil {
			t.Fatal("stalled write silently succeeded")
		}
	}
	if s.Stats() != (ServerStats{}) {
		t.Fatal("outbound timeout leaked workers", s.Stats())
	}
}
func TestSessionAdmissionAndAuthTimeout(t *testing.T) {
	c := cfg()
	c.MaxSessions = 1
	c.HandshakeTimeout = 30 * time.Millisecond
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, a, noHandler) }()
	deadline := time.Now().Add(time.Second)
	for s.Stats().Sessions == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	x, y := net.Pipe()
	defer y.Close()
	if e = s.Serve(ctx, x, noHandler); !errors.Is(e, ErrSessionLimit) {
		t.Fatal(e)
	}
	if e = <-done; e == nil {
		t.Fatal("auth timeout missing")
	}
	if s.Stats() != (ServerStats{}) {
		t.Fatal(s.Stats())
	}
}
func TestV1CannotUseV2HeartbeatAndWasteIsBounded(t *testing.T) {
	c := start(t, cfg(), noHandler)
	login(t, c, 1)
	c.send(t, wire(cmdWaste, 0, make([]byte, 4096)))
	_ = c.write(wire(cmdHeartRequest, 0, nil))
	c.next(t, cmdAlert, 0)
	e := <-c.result
	c.result <- e
	if !errors.Is(e, ErrProtocol) {
		t.Fatal(e)
	}
}
