package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	SS "github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

var ss2022LifecycleMethods = []string{SS.AES128GCM2022, SS.AES256GCM2022, SS.ChaCha20Poly13052022}

// Independent request builder: no production SS encoder is used. A padding-only
// initial request is followed by large authenticated records, exercising the
// resident receive allocation while Write2022To is blocked in the target.
func ss2022LifecycleWire(t *testing.T, method string, target Address, records int) ([]byte, []byte, []byte) {
	t.Helper()
	keySize := 32
	if method == SS.AES128GCM2022 {
		keySize = 16
	}
	key := bytes.Repeat([]byte{0x41}, keySize)
	salt := bytes.Repeat([]byte{0x6b}, keySize)
	sub := make([]byte, keySize)
	blake3.DeriveKey(sub, "shadowsocks 2022 session subkey", append(append([]byte(nil), key...), salt...))
	var a cipher.AEAD
	var err error
	if method == SS.ChaCha20Poly13052022 {
		a, err = chacha20poly1305.New(sub)
	} else {
		var b cipher.Block
		b, err = aes.NewCipher(sub)
		if err == nil {
			a, err = cipher.NewGCM(b)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	variable := append(peerAddr(target, false), 0, 1, 0)
	fixed := binary.BigEndian.AppendUint64([]byte{0}, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))
	nonce := make([]byte, 12)
	seal := func(p []byte) []byte {
		b := a.Seal(nil, nonce, p, nil)
		for i := range nonce {
			nonce[i]++
			if nonce[i] != 0 {
				break
			}
		}
		return b
	}
	wire := append(append([]byte(nil), salt...), seal(fixed)...)
	wire = append(wire, seal(variable)...)
	plain := bytes.Repeat([]byte{0x5b}, 32734)
	for i := 0; i < records; i++ {
		wire = append(wire, seal(binary.BigEndian.AppendUint16(nil, uint16(len(plain))))...)
		wire = append(wire, seal(plain)...)
	}
	return wire, key, plain
}

type ss2022LifecycleClient struct {
	input       *bytes.Reader
	closed      chan struct{}
	once        sync.Once
	beforeClose func()
}

func (c *ss2022LifecycleClient) Read(p []byte) (int, error) {
	n, err := c.input.Read(p)
	if n > 0 {
		return n, nil
	}
	if err != nil {
		<-c.closed
		return 0, net.ErrClosed
	}
	return n, err
}
func (c *ss2022LifecycleClient) Write(p []byte) (int, error) { return len(p), nil }
func (c *ss2022LifecycleClient) Close() error {
	c.once.Do(func() {
		if c.beforeClose != nil {
			c.beforeClose()
		}
		close(c.closed)
	})
	return nil
}
func (c *ss2022LifecycleClient) CloseWrite() error { return nil }
func (c *ss2022LifecycleClient) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *ss2022LifecycleClient) RemoteAddr() net.Addr             { return c.LocalAddr() }
func (c *ss2022LifecycleClient) SetDeadline(time.Time) error      { return nil }
func (c *ss2022LifecycleClient) SetReadDeadline(time.Time) error  { return nil }
func (c *ss2022LifecycleClient) SetWriteDeadline(time.Time) error { return nil }

type ss2022LifecycleTarget struct {
	entered                                 chan []byte
	closed                                  chan struct{}
	readEnd                                 chan struct{}
	deadlineSet                             chan struct{}
	once, enterOnce, readOnce, deadlineOnce sync.Once
	readEOF                                 bool
}

func (c *ss2022LifecycleTarget) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.readEnd:
		if c.readEOF {
			return 0, io.EOF
		}
		return 0, io.ErrUnexpectedEOF
	}
}
func (c *ss2022LifecycleTarget) Write(p []byte) (int, error) {
	c.enterOnce.Do(func() { c.entered <- p })
	<-c.closed
	return 0, net.ErrClosed
}
func (c *ss2022LifecycleTarget) Close() error      { c.once.Do(func() { close(c.closed) }); return nil }
func (c *ss2022LifecycleTarget) CloseWrite() error { return nil }
func (c *ss2022LifecycleTarget) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}
func (c *ss2022LifecycleTarget) RemoteAddr() net.Addr { return c.LocalAddr() }
func (c *ss2022LifecycleTarget) SetDeadline(time.Time) error {
	c.deadlineOnce.Do(func() { close(c.deadlineSet) })
	return nil
}
func (c *ss2022LifecycleTarget) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *ss2022LifecycleTarget) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func TestSS2022BlockedUploadShutdown(t *testing.T) {
	for _, method := range ss2022LifecycleMethods {
		for _, mode := range []string{"cancel", "idle", "target-error", "drain-cancel"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				wire, key, plain := ss2022LifecycleWire(t, method, Address{"127.0.0.1", 80}, 1)
				srv, err := SS.NewServer(SS.Config{Method: method, Key: key})
				if err != nil {
					t.Fatal(err)
				}
				target := &ss2022LifecycleTarget{entered: make(chan []byte, 1), closed: make(chan struct{}), readEnd: make(chan struct{}), deadlineSet: make(chan struct{}), readEOF: mode == "drain-cancel"}
				var clientFirst atomic.Bool
				raw := &ss2022LifecycleClient{input: bytes.NewReader(wire), closed: make(chan struct{}), beforeClose: func() {
					select {
					case <-target.closed:
					default:
						clientFirst.Store(true)
					}
				}}
				codec, err := srv.Accept(raw)
				if err != nil {
					t.Fatal(err)
				}
				s := &Server{pool: newBufferPool(16384, 1)}
				s.cfg.Limits.DrainTimeout = Duration(time.Second)
				if mode == "idle" {
					s.cfg.Limits.TCPIdle = Duration(30 * time.Millisecond)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- s.relaySS2022(ctx, &encryptedStream{raw, codec}, &ss2022DownConn{target}) }()
				// Cleanup is independent of the relay close order: even the unfixed code
				// is released and JOINED before any failing assertion returns.
				defer func() { target.Close(); raw.Close(); codec.Close() }()
				select {
				case got := <-target.entered:
					if !bytes.Equal(got, plain) {
						t.Error("target write plaintext mismatch")
					}
				case <-time.After(time.Second):
					target.Close()
					cancel()
					<-done
					t.Fatal("target write did not block")
				}
				switch mode {
				case "cancel":
					cancel()
				case "target-error":
					target.readOnce.Do(func() { close(target.readEnd) })
				case "drain-cancel":
					target.readOnce.Do(func() { close(target.readEnd) })
					select {
					case <-target.deadlineSet:
					case <-time.After(time.Second):
						target.Close()
						cancel()
						<-done
						t.Fatal("drain phase not entered")
					}
					cancel()
				}
				timedOut := false
				select {
				case <-done:
				case <-time.After(150 * time.Millisecond):
					timedOut = true
					target.Close()
					cancel()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("forced target cleanup failed to join relay")
					}
				}
				if timedOut {
					t.Error("shutdown blocked; forced target close released rMu and joined all relay workers")
				}
				if clientFirst.Load() {
					t.Error("client codec Close was entered before target Close")
				}
			})
		}
	}
}

// Real Start -> accepted raw TCP registration -> Server.Close deadline ->
// s.cancel -> SS2022 relay. A live target stops reading, not a synthetic Stop.
func TestSS2022BlockedUploadServerStop(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			tcp := c.(*net.TCPConn)
			tcp.SetReadBuffer(1024)
			accepted <- tcp
		} else {
			accepted <- nil
		}
	}()
	s := startTest(t, ssIn(), func(c *Config) { c.Limits.TCPIdle = Duration(10 * time.Second) })
	peer := dialPeer(t, s, nil)
	wire, _, _ := ss2022LifecycleWire(t, SS.AES128GCM2022, addrFromNet(ln.Addr()), 256)
	sent := make(chan error, 1)
	go func() { sent <- writeAll(peer, wire) }()
	var target *net.TCPConn
	acceptedSeen, sentSeen := false, false
	cleanup := func() {
		ln.Close()
		if !acceptedSeen {
			target = <-accepted
			acceptedSeen = true
		}
		if target != nil {
			target.Close()
		}
		peer.Close()
		if !sentSeen {
			<-sent
			sentSeen = true
		}
	}
	defer cleanup()
	select {
	case target = <-accepted:
		acceptedSeen = true
		if target == nil {
			t.Fatal("target accept failed")
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
			if strings.Contains(stack, "github.com/shui1iao/Kat/internal/ss.(*TCPConn).Write2022To") && strings.Contains(stack, "internal/poll.(*FD).Write") {
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
		t.Fatal("real target Write was not observed blocked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Close(ctx) }()
	timedOut := false
	select {
	case err = <-stopped:
	case <-time.After(200 * time.Millisecond):
		timedOut = true
		cleanup()
		select {
		case err = <-stopped:
		case <-time.After(time.Second):
			t.Fatal("forced TCP cleanup failed to join Server.Close")
		}
	}
	cleanup()
	if timedOut {
		t.Error("Server.Close deadlocked after real target write blocked; forced target TCP close recovered it")
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Active != 0 || st.Handshakes != 0 {
		t.Fatal("server resources not reclaimed", st)
	}
}
