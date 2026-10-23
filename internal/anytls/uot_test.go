package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

func TestUoTIndependentFixedFixturesBothModes(t *testing.T) {
	for _, mode := range []string{"connect", "nonconnect"} {
		t.Run(mode, func(t *testing.T) {
			received := make(chan []Address, 1)
			done := make(chan error, 1)
			c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) {
				if r.UDP == nil {
					done <- ErrProtocol
					return
				}
				count := 3
				if r.UDP.Connected() {
					count = 2
				}
				var targets []Address
				for i := 0; i < count; i++ {
					a, p, e := r.UDP.ReadPacket()
					if e != nil {
						done <- e
						return
					}
					targets = append(targets, a)
					if e = r.UDP.WritePacket(a, p); e != nil {
						done <- e
						return
					}
				}
				if r.UDP.Connected() {
					if e := r.UDP.WritePacket(Address{"different", 1}, nil); !errors.Is(e, ErrConnectedAddress) {
						done <- e
						return
					}
				}
				received <- targets
				done <- nil
			})
			login(t, c, 2)
			c.send(t, wire(cmdSYN, 1, nil))
			c.next(t, cmdSYNACK, 1)
			magic := targetBytes(t, Address{MagicUDPHost, 443})
			key := "uot_" + mode
			fixture := fixtures(t)[key]
			// A fragmented magic SOCKS target, UoT request and datagrams; PSH boundaries
			// deliberately have no relationship to the UoT address/length/payload fields.
			combined := append(magic, fixture...)
			for _, b := range combined {
				c.send(t, wire(cmdPSH, 1, []byte{b}))
			}
			var out []byte
			for {
				f := <-c.frames
				if f.cmd == cmdPSH {
					out = append(out, f.data...)
				}
				if f.cmd == cmdFIN {
					break
				}
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			targets := <-received
			if mode == "connect" {
				if !bytes.Equal(out, fixture[8:]) || len(targets) != 2 || targets[0] != (Address{"127.0.0.1", 443}) {
					t.Fatalf("connect response %x %v", out, targets)
				}
			} else {
				if !bytes.Equal(out, fixture[8:]) || len(targets) != 3 || targets[1] != (Address{"x", 53}) || targets[2] != (Address{"::1", 53}) {
					t.Fatalf("nonconnect response %x %v", out, targets)
				}
			}
		})
	}
}
func TestUoTTruncationAndAddressEnums(t *testing.T) {
	for _, mode := range []bool{true, false} {
		for _, cut := range []int{1, 2, 5} {
			name := "nonconnect"
			if mode {
				name = "connect"
			}
			t.Run(name+string(rune('0'+cut)), func(t *testing.T) {
				result := make(chan error, 1)
				ready := make(chan struct{})
				c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) {
					close(ready)
					_, _, e := r.UDP.ReadPacket()
					result <- e
				})
				login(t, c, 2)
				c.send(t, wire(cmdSYN, 1, nil))
				c.next(t, cmdSYNACK, 1)
				initial := targetBytes(t, Address{MagicUDPHost, 443})
				flag := byte(0)
				if mode {
					flag = 1
				}
				initial = append(initial, flag)
				initial = append(initial, targetBytes(t, Address{"127.0.0.1", 443})...)
				c.send(t, wire(cmdPSH, 1, initial))
				<-ready
				packet := []byte{0, 5, 'a', 'b', 'c', 'd', 'e'}
				if !mode {
					a, _ := (Address{"127.0.0.1", 443}).marshal(true)
					packet = append(a, packet...)
				}
				c.send(t, wire(cmdPSH, 1, packet[:cut]))
				c.send(t, wire(cmdFIN, 1, nil))
				if e := <-result; !errors.Is(e, io.ErrUnexpectedEOF) {
					t.Fatal("UoT truncation not rejected", e)
				}
			})
		}
	}
	for _, a := range []Address{{"127.0.0.1", 53}, {"::1", 53}, {"x", 53}} {
		b, e := a.marshal(true)
		if e != nil {
			t.Fatal(e)
		}
		got, e := readAddress(bytes.NewReader(b), true)
		if e != nil || got != a {
			t.Fatal(got, e)
		}
		if a.Host == "x" && b[0] != 2 {
			t.Fatal("UoT domain enum")
		}
	}
	if _, e := readAddress(bytes.NewReader([]byte{3, 1, 'x', 0, 53}), true); !errors.Is(e, ErrProtocol) {
		t.Fatal("SOCKS enum accepted for UoT", e)
	}
}
func TestUoTMaximumLengthAndOutputOwnership(t *testing.T) {
	done := make(chan error, 1)
	c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) {
		a, p, e := r.UDP.ReadPacket()
		if e == nil && len(p) != 65535 {
			e = ErrProtocol
		}
		if e == nil {
			e = r.UDP.WritePacket(a, p)
		}
		if e == nil {
			e = r.UDP.WritePacket(a, make([]byte, 65536))
			if errors.Is(e, ErrProtocol) {
				e = nil
			} else {
				e = ErrProtocol
			}
		}
		done <- e
	})
	login(t, c, 2)
	c.send(t, wire(cmdSYN, 1, nil))
	c.next(t, cmdSYNACK, 1)
	body := targetBytes(t, Address{MagicUDPHost, 443})
	body = append(body, 1)
	body = append(body, targetBytes(t, Address{"127.0.0.1", 443})...)
	body = binary.BigEndian.AppendUint16(body, 65535)
	data := bytes.Repeat([]byte{0x51}, 65535)
	body = append(body, data...)
	for len(body) > 0 {
		n := min(len(body), 16384)
		c.send(t, wire(cmdPSH, 1, body[:n]))
		body = body[n:]
	}
	var got []byte
	for len(got) < 65537 {
		f := c.next(t, cmdPSH, 1)
		got = append(got, f.data...)
	}
	if binary.BigEndian.Uint16(got[:2]) != 65535 || !bytes.Equal(got[2:], data) {
		t.Fatal("large datagram corrupted")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestReadMemoryChargedUntilFrameFreed(t *testing.T) {
	stCh := make(chan *Stream, 1)
	release := make(chan struct{})
	c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) {
		stCh <- st
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	login(t, c, 2)
	c.send(t, wire(cmdSYN, 1, nil))
	c.next(t, cmdSYNACK, 1)
	data := append(targetBytes(t, Address{"x", 80}), bytes.Repeat([]byte{1}, 100)...)
	c.send(t, wire(cmdPSH, 1, data))
	st := <-stCh
	stats := st.SessionStats()
	if stats.InboundBytes != len(data)+7 {
		t.Fatalf("retained frame allocation undercharged: %+v", stats)
	}
	close(release)
}
func TestTargetAndSessionTimeoutBudgetCleanup(t *testing.T) {
	cc := cfg()
	cc.TargetTimeout = 20 * time.Millisecond
	c := start(t, cc, noHandler)
	login(t, c, 2)
	c.send(t, wire(cmdSYN, 1, nil))
	c.next(t, cmdSYNACK, 1)
	c.next(t, cmdFIN, 1)
	deadline := time.Now().Add(time.Second)
	for c.server.Stats().Streams != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.server.Stats().Streams != 0 {
		t.Fatal("target timeout leaked worker")
	}
	// A stream quota rejection is a SYNACK error, not an unbounded pending worker.
	cc = cfg()
	cc.MaxStreams = 1
	opened := make(chan struct{}, 1)
	limited := start(t, cc, func(ctx context.Context, st *Stream, r Request) { opened <- struct{}{}; <-ctx.Done() })
	login(t, limited, 2)
	limited.send(t, wire(cmdSYN, 1, nil))
	limited.next(t, cmdSYNACK, 1)
	limited.send(t, wire(cmdPSH, 1, targetBytes(t, Address{"x", 80})))
	<-opened
	limited.send(t, wire(cmdSYN, 2, nil))
	if f := limited.next(t, cmdSYNACK, 2); len(f.data) == 0 {
		t.Fatal("missing quota failure")
	}
}
