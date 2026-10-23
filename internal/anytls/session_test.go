package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testFrame struct {
	cmd  byte
	id   uint32
	data []byte
}

func wire(c byte, id uint32, p []byte) []byte {
	b := make([]byte, 7+len(p))
	b[0] = c
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(p)))
	copy(b[7:], p)
	return b
}
func fixtures(t *testing.T) map[string][]byte {
	t.Helper()
	b, e := os.ReadFile("testdata/spec-fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var raw map[string]string
	if e = json.Unmarshal(b, &raw); e != nil {
		t.Fatal(e)
	}
	out := map[string][]byte{}
	for k, v := range raw {
		out[k], e = hex.DecodeString(v)
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func cfg() Config {
	return Config{Password: "fixture-password", UserID: "fixture-user", HandshakeTimeout: time.Second, TargetTimeout: time.Second, SlowConsumerTimeout: time.Second, WriteTimeout: time.Second, MaxSessions: 8, MaxStreams: 8, MaxTotalStreams: 16}
}

type testClient struct {
	p      net.Conn
	mu     sync.Mutex
	frames chan testFrame
	result chan error
	server *Server
	cancel context.CancelFunc
}

func start(t *testing.T, c Config, h Handler) *testClient {
	t.Helper()
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	cl := &testClient{p: b, frames: make(chan testFrame, 64), result: make(chan error, 1), server: s, cancel: cancel}
	go func() { cl.result <- s.Serve(ctx, a, h) }()
	go func() {
		defer close(cl.frames)
		for {
			var h [7]byte
			if _, e := io.ReadFull(b, h[:]); e != nil {
				return
			}
			p := make([]byte, binary.BigEndian.Uint16(h[5:]))
			if _, e := io.ReadFull(b, p); e != nil {
				return
			}
			f := testFrame{h[0], binary.BigEndian.Uint32(h[1:5]), p}
			if f.cmd == cmdHeartRequest {
				_ = cl.write(wire(cmdHeartResponse, f.id, nil))
			}
			select {
			case cl.frames <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		b.Close()
		select {
		case <-cl.result:
		case <-time.After(2 * time.Second):
			t.Error("Serve/handler did not cancel")
		}
	})
	return cl
}
func (c *testClient) write(b []byte) error { c.mu.Lock(); defer c.mu.Unlock(); return writeAll(c.p, b) }
func (c *testClient) send(t *testing.T, b []byte) {
	t.Helper()
	if e := c.write(b); e != nil {
		t.Fatal(e)
	}
}
func (c *testClient) next(t *testing.T, cmd byte, id uint32) testFrame {
	t.Helper()
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				t.Fatalf("closed waiting for cmd%d id%d", cmd, id)
			}
			if f.cmd == cmd && f.id == id {
				return f
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for cmd%d id%d", cmd, id)
		}
	}
}
func login(t *testing.T, c *testClient, version int) {
	t.Helper()
	v := fixtures(t)
	c.send(t, v["auth"])
	name := "settings_v2"
	if version == 1 {
		name = "settings_v1"
	}
	c.send(t, v[name])
	if version == 2 {
		f := c.next(t, cmdServerSettings, 0)
		if string(f.data) != "v=2" {
			t.Fatal(f)
		}
	}
}
func targetBytes(t *testing.T, a Address) []byte {
	t.Helper()
	b, e := a.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func noHandler(context.Context, *Stream, Request) {}
func TestFixedSpecFixturesV1V2ReuseFIN(t *testing.T) {
	for _, v := range []int{1, 2} {
		t.Run(strconv.Itoa(v), func(t *testing.T) {
			calls := make(chan Request, 4)
			read := make(chan string, 4)
			c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) {
				calls <- r
				p, e := io.ReadAll(st)
				if e != nil {
					read <- "error:" + e.Error()
				} else {
					read <- string(p)
				}
			})
			login(t, c, v)
			f := fixtures(t)
			for i := uint32(1); i <= 2; i++ {
				c.send(t, wire(cmdSYN, i, nil))
				if v == 2 {
					ack := c.next(t, cmdSYNACK, i)
					if len(ack.data) != 0 {
						t.Fatal(ack)
					}
				}
				p := append(targetBytes(t, Address{"127.0.0.1", 443}), []byte("hello")...)
				if i == 1 {
					c.send(t, f["target_payload"])
				} else {
					c.send(t, wire(cmdPSH, i, p))
				}
				r := <-calls
				if r.Target != (Address{"127.0.0.1", 443}) || r.UserID != "fixture-user" || r.Version != v {
					t.Fatal(r)
				}
				c.send(t, wire(cmdFIN, i, nil))
				if got := <-read; got != "hello" {
					t.Fatal(got)
				}
			}
			if c.server.Stats().Sessions != 1 {
				t.Fatal("reuse lost session")
			}
			select {
			case f := <-c.frames:
				if f.cmd == cmdFIN {
					t.Fatal("peer FIN echoed")
				}
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}
func TestPaddingUpdateHeartbeatAndServerFirst(t *testing.T) {
	cconfig := cfg()
	cconfig.PaddingScheme = "stop=2\n0=16-16\n1=80-160,c,160-200"
	handlerError := make(chan error, 1)
	c := start(t, cconfig, func(ctx context.Context, st *Stream, r Request) {
		if e := st.CloseWrite(); !errors.Is(e, ErrHalfCloseUnsupported) {
			handlerError <- e
			return
		}
		if _, e := st.Write([]byte("welcome")); e != nil {
			handlerError <- e
			return
		}
		pingctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		handlerError <- st.Ping(pingctx)
	})
	login(t, c, 2)
	update := c.next(t, cmdPadding, 0)
	if string(update.data) != cconfig.PaddingScheme {
		t.Fatal(string(update.data))
	}
	c.send(t, wire(cmdHeartRequest, 9, nil))
	c.next(t, cmdHeartResponse, 9)
	c.send(t, wire(cmdSYN, 1, nil))
	c.next(t, cmdSYNACK, 1)
	c.send(t, wire(cmdPSH, 1, targetBytes(t, Address{"x", 80})))
	if f := c.next(t, cmdPSH, 1); string(f.data) != "welcome" {
		t.Fatal(f)
	}
	if e := <-handlerError; e != nil {
		t.Fatal(e)
	}
	c.next(t, cmdFIN, 1)
}
func TestRejectAuthenticationAndIllegalCommands(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{{"settings-order", wire(cmdSYN, 1, nil)}, {"unknown", wire(99, 0, nil)}, {"duplicate-settings", nil}, {"duplicate-syn", nil}, {"unknown-psh", wire(cmdPSH, 7, []byte("x"))}, {"syn-with-data", wire(cmdSYN, 1, []byte("x"))}, {"zero-stream", wire(cmdSYN, 0, nil)}, {"client-alert", wire(cmdAlert, 0, nil)}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := start(t, cfg(), noHandler)
			v := fixtures(t)
			if tc.name == "settings-order" {
				c.send(t, v["auth"])
			} else {
				login(t, c, 2)
			}
			data := tc.data
			switch tc.name {
			case "duplicate-settings":
				data = v["settings_v2"]
			case "duplicate-syn":
				c.send(t, wire(cmdSYN, 1, nil))
				c.next(t, cmdSYNACK, 1)
				data = wire(cmdSYN, 1, nil)
			}
			_ = c.write(data)
			c.next(t, cmdAlert, 0)
			e := <-c.result
			c.result <- e
			if !errors.Is(e, ErrProtocol) {
				t.Fatal(e)
			}
		})
	}
	for _, kind := range []string{"password", "padding-short"} {
		t.Run(kind, func(t *testing.T) {
			called := false
			c := start(t, cfg(), func(context.Context, *Stream, Request) { called = true })
			f := bytes.Clone(fixtures(t)["auth"])
			if kind == "password" {
				f[0] ^= 1
				_ = c.write(f)
			} else {
				_ = c.write(f[:35])
				c.p.Close()
			}
			e := <-c.result
			c.result <- e
			if e == nil || called {
				t.Fatal(e, called)
			}
		})
	}
}
func TestSettingsAndFrameTruncation(t *testing.T) {
	for _, setting := range []string{"v=2\nclient=x", "v=0\nclient=x\npadding-md5=00000000000000000000000000000000", "v=2\nv=2\nclient=x\npadding-md5=00000000000000000000000000000000"} {
		c := start(t, cfg(), noHandler)
		c.send(t, fixtures(t)["auth"])
		_ = c.write(wire(cmdSettings, 0, []byte(setting)))
		c.next(t, cmdAlert, 0)
		e := <-c.result
		c.result <- e
		if !errors.Is(e, ErrProtocol) {
			t.Fatal(e)
		}
	}
	for _, cut := range []int{1, 6, 9} {
		c := start(t, cfg(), noHandler)
		login(t, c, 2)
		data := wire(cmdPSH, 1, []byte("payload"))
		if cut == 9 {
			c.send(t, wire(cmdSYN, 1, nil))
			c.next(t, cmdSYNACK, 1)
		}
		_ = c.write(data[:cut])
		c.p.Close()
		e := <-c.result
		c.result <- e
		if e == nil {
			t.Fatal("truncated frame accepted", cut)
		}
	}
}
func TestSlowFlowBudgetAndCancellationRecovery(t *testing.T) {
	for _, recover := range []bool{false, true} {
		name := "timeout"
		if recover {
			name = "cancel-recover"
		}
		t.Run(name, func(t *testing.T) {
			cc := cfg()
			cc.StreamInboundFrames = 1
			cc.StreamInboundBytes = 32
			cc.SessionInboundFrames = 2
			cc.SessionInboundBytes = 64
			cc.SlowConsumerTimeout = 60 * time.Millisecond
			opened := make(chan *Stream, 2)
			c := start(t, cc, func(ctx context.Context, st *Stream, r Request) {
				opened <- st
				if st.ID() == 1 {
					<-ctx.Done()
					return
				}
				p := make([]byte, 2)
				_, e := io.ReadFull(st, p)
				if e == nil {
					st.Write(p)
				}
			})
			login(t, c, 2)
			c.send(t, wire(cmdSYN, 1, nil))
			c.next(t, cmdSYNACK, 1)
			initial := append(targetBytes(t, Address{"x", 80}), []byte("ABCD")...)
			c.send(t, wire(cmdPSH, 1, initial))
			st := <-opened
			waiting := make(chan error, 1)
			go func() { waiting <- c.write(wire(cmdPSH, 1, []byte("EFGH"))) }()
			time.Sleep(10 * time.Millisecond)
			stats := st.SessionStats()
			if stats.InboundFrames > 2 || stats.InboundBytes > 64 {
				t.Fatal(stats)
			}
			if !recover {
				c.next(t, cmdAlert, 0)
				e := <-c.result
				c.result <- e
				if !errors.Is(e, ErrSlowConsumer) {
					t.Fatal(e)
				}
				<-waiting
				return
			}
			if e := st.Close(); e != nil {
				t.Fatal(e)
			}
			if e := <-waiting; e != nil {
				t.Fatal(e)
			}
			c.next(t, cmdFIN, 1)
			c.send(t, wire(cmdSYN, 2, nil))
			c.next(t, cmdSYNACK, 2)
			c.send(t, wire(cmdPSH, 2, append(targetBytes(t, Address{"x", 80}), []byte("OK")...)))
			<-opened
			if f := c.next(t, cmdPSH, 2); string(f.data) != "OK" {
				t.Fatal(f)
			}
		})
	}
}
func TestReadDeadlineTargetTimeoutAndLimits(t *testing.T) {
	results := make(chan error, 1)
	opened := make(chan *Stream, 1)
	c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) {
		opened <- st
		st.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, e := st.Read(make([]byte, 1))
		if !errors.Is(e, os.ErrDeadlineExceeded) {
			results <- e
			return
		}
		st.SetReadDeadline(time.Time{})
		p := make([]byte, 2)
		_, e = io.ReadFull(st, p)
		if e == nil {
			_, e = st.Write(p)
		}
		results <- e
	})
	login(t, c, 2)
	c.send(t, wire(cmdSYN, 1, nil))
	c.next(t, cmdSYNACK, 1)
	c.send(t, wire(cmdPSH, 1, targetBytes(t, Address{"::1", 80})))
	<-opened
	time.Sleep(35 * time.Millisecond)
	c.send(t, wire(cmdPSH, 1, []byte("OK")))
	if f := c.next(t, cmdPSH, 1); string(f.data) != "OK" {
		t.Fatal(f)
	}
	if e := <-results; e != nil {
		t.Fatal(e)
	}
	for _, invalid := range []Config{{Password: ""}, {Password: "x", MaxSessions: -1}, {Password: "x", PaddingScheme: "stop=2\n0=7-1"}, {Password: "x", PaddingScheme: "stop=0"}, {Password: "x", MaxFrameData: 65536}} {
		if _, e := NewServer(invalid); !errors.Is(e, ErrConfig) {
			t.Fatal(invalid, e)
		}
	}
	// Ensure a single over-budget valid frame fails explicitly, not by dropping TCP data.
	small := cfg()
	small.StreamInboundBytes = 8
	limited := start(t, small, noHandler)
	login(t, limited, 2)
	limited.send(t, wire(cmdSYN, 1, nil))
	limited.next(t, cmdSYNACK, 1)
	_ = limited.write(wire(cmdPSH, 1, make([]byte, 16)))
	limited.next(t, cmdAlert, 0)
	e := <-limited.result
	limited.result <- e
	if !errors.Is(e, ErrQueueLimit) {
		t.Fatal(e)
	}
}
func TestStandaloneFixtureAuthenticationBytes(t *testing.T) {
	f := fixtures(t)
	digest := sha256.Sum256([]byte("fixture-password"))
	if !bytes.Equal(digest[:], f["auth"][:32]) {
		t.Fatal("independent hashlib fixture mismatch")
	}
	if hex.EncodeToString(wire(cmdServerSettings, 0, []byte("v=2"))) != "0a000000000003763d32" {
		t.Fatal("fixed header layout")
	}
	for _, f := range []string{"", strings.Repeat("x", 4097)} {
		if _, _, e := parseSettings([]byte(f)); e == nil {
			t.Fatal("invalid settings accepted")
		}
	}
}
