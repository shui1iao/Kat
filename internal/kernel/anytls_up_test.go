package kernel

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type anyTLSUpBlockedTarget struct {
	entered     chan []byte
	closed      chan struct{}
	once, enter sync.Once
}

func (c *anyTLSUpBlockedTarget) Read(p []byte) (int, error) { <-c.closed; return 0, net.ErrClosed }
func (c *anyTLSUpBlockedTarget) Write(p []byte) (int, error) {
	c.enter.Do(func() { c.entered <- p })
	<-c.closed
	return 0, net.ErrClosed
}
func (c *anyTLSUpBlockedTarget) Close() error { c.once.Do(func() { close(c.closed) }); return nil }
func (c *anyTLSUpBlockedTarget) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *anyTLSUpBlockedTarget) RemoteAddr() net.Addr             { return c.LocalAddr() }
func (c *anyTLSUpBlockedTarget) SetDeadline(time.Time) error      { return nil }
func (c *anyTLSUpBlockedTarget) SetReadDeadline(time.Time) error  { return nil }
func (c *anyTLSUpBlockedTarget) SetWriteDeadline(time.Time) error { return nil }

func TestAnyTLSUpBlockedTargetLifecycle(t *testing.T) {
	for _, mode := range []string{"ctx-cancel", "peer-fin", "session-close", "idle"} {
		t.Run(mode, func(t *testing.T) {
			codec, e := A.NewServer(A.Config{Password: "fixture-password", WriteTimeout: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			server, peer := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			target := &anyTLSUpBlockedTarget{entered: make(chan []byte, 1), closed: make(chan struct{})}
			relay := &Server{pool: newBufferPool(16384, 2)}
			if mode == "idle" {
				relay.cfg.Limits.TCPIdle = Duration(30 * time.Millisecond)
			}
			handled := make(chan A.SessionStats, 1)
			served := make(chan error, 1)
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				var h [7]byte
				for {
					if _, e := io.ReadFull(peer, h[:]); e != nil {
						return
					}
					size := int(h[5])<<8 | int(h[6])
					if _, e := io.CopyN(io.Discard, peer, int64(size)); e != nil {
						return
					}
				}
			}()
			go func() {
				served <- codec.Serve(ctx, server, func(stctx context.Context, st *A.Stream, r A.Request) {
					relay.relayAnyTLS(stctx, &anyStream{server, st}, target)
					handled <- st.SessionStats()
				})
			}()
			joined := false
			defer func() {
				target.Close()
				cancel()
				peer.Close()
				server.Close()
				if !joined {
					select {
					case <-served:
					case <-time.After(time.Second):
						t.Error("Serve failed to join after forced cleanup")
					}
				}
				<-drained
			}()
			sum := sha256.Sum256([]byte("fixture-password"))
			md := md5.Sum([]byte(A.DefaultPaddingScheme))
			auth := append(append([]byte(nil), sum[:]...), 0, 0)
			auth = append(auth, atFrame(4, 0, []byte(fmt.Sprintf("v=2\npadding-md5=%s", hex.EncodeToString(md[:]))))...)
			auth = append(auth, atFrame(1, 1, nil)...)
			auth = append(auth, atFrame(2, 1, peerAddr(Address{"127.0.0.1", 80}, false))...)
			payload := bytes.Repeat([]byte{0x56}, 65535)
			auth = append(auth, atFrame(2, 1, payload)...)
			sent := make(chan error, 1)
			go func() { sent <- writeAll(peer, auth) }()
			select {
			case e := <-sent:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				peer.Close()
				<-sent
				t.Fatal("authenticated request blocked")
			}
			select {
			case b := <-target.entered:
				if !bytes.Equal(b, payload) {
					t.Error("whole frame not passed directly", len(b))
				}
			case <-time.After(time.Second):
				t.Fatal("target write not entered")
			}
			switch mode {
			case "ctx-cancel":
				cancel()
			case "peer-fin":
				if e := writeAll(peer, atFrame(3, 1, nil)); e != nil {
					t.Fatal(e)
				}
			case "session-close":
				peer.Close()
			}
			select {
			case st := <-handled:
				if st.InboundBytes != 0 || st.InboundFrames != 0 {
					t.Error("inbound accounting survived completed I/O", st)
				}
			case <-time.After(250 * time.Millisecond):
				target.Close()
				cancel()
				t.Error("relay did not stop blocked target Write")
			}
			target.Close()
			cancel()
			peer.Close()
			server.Close()
			select {
			case <-served:
				joined = true
			case <-time.After(time.Second):
				t.Fatal("session failed to join handlers")
			}
		})
	}
}

func TestAnyTLSUpBlockedTargetServerStop(t *testing.T) {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			accepted <- nil
			return
		}
		tcp := c.(*net.TCPConn)
		tcp.SetReadBuffer(1024)
		accepted <- tcp
	}()
	cert, roots := testCert(t)
	s := startTest(t, anyIn(cert), nil)
	peer := atBegin(t, s, roots, 2)
	sent := make(chan error, 1)
	go func() {
		wire := atFrame(1, 1, nil)
		wire = append(wire, atFrame(2, 1, peerAddr(addrFromNet(ln.Addr()), false))...)
		if e := writeAll(peer, wire); e != nil {
			sent <- e
			return
		}
		frame := atFrame(2, 1, bytes.Repeat([]byte{0x6a}, 65535))
		for i := 0; i < 128; i++ {
			if e := writeAll(peer, frame); e != nil {
				sent <- e
				return
			}
		}
		sent <- nil
	}()
	var target *net.TCPConn
	seen, senderDone := false, false
	cleanup := func() {
		ln.Close()
		if !seen {
			target = <-accepted
			seen = true
		}
		if target != nil {
			target.Close()
		}
		peer.Close()
		if !senderDone {
			<-sent
			senderDone = true
		}
	}
	defer cleanup()
	select {
	case target = <-accepted:
		seen = true
		if target == nil {
			t.Fatal("accept failed")
		}
	case <-time.After(time.Second):
		t.Fatal("target not dialed")
	}
	blocked := false
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		stacks := make([]byte, 1<<20)
		n := runtime.Stack(stacks, true)
		for _, stack := range strings.Split(string(stacks[:n]), "\n\n") {
			if strings.Contains(stack, "internal/anytls.(*Stream).WriteTCPTo") && strings.Contains(stack, "internal/poll.(*FD).Write") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !blocked {
		cleanup()
		t.Fatal("real TCP target Write was not observed blocked")
	}
	stopctx, stopcancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stopcancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Close(stopctx) }()
	select {
	case <-stopped:
	case <-time.After(250 * time.Millisecond):
		cleanup()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("forced cleanup failed to join Server.Close")
		}
		t.Error("Server.Close failed to unblock owned TCP upload")
	}
	cleanup()
	if st := s.Stats(); st.Active != 0 || s.logical.Load() != 0 {
		t.Fatal("server resources leaked", st)
	}
}
