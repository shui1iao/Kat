package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSingleOwnedWireChargedThroughWriteAndCleared(t *testing.T) {
	for _, cancelQueued := range []bool{false, true} {
		server, e := NewServer(cfg())
		if e != nil {
			t.Fatal(e)
		}
		a, b := net.Pipe()
		ctx, cancel := context.WithCancelCause(context.Background())
		sess := &session{server: server, transport: a, ctx: ctx, cancel: cancel, change: make(chan struct{}), writerDone: make(chan struct{})}
		payload := bytes.Repeat([]byte{0x44}, 4096)
		sent := make(chan error, 1)
		go func() { sent <- sess.send(cmdPSH, 19, payload, nil, time.Time{}) }()
		var frame *outbound
		end := time.Now().Add(time.Second)
		for time.Now().Before(end) {
			sess.mu.Lock()
			if len(sess.out) > 0 {
				frame = sess.out[0]
			}
			sess.mu.Unlock()
			if frame != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if frame == nil {
			t.Fatal("enqueue did not happen")
		}
		sess.mu.Lock()
		owned := frame.wire
		if sess.outBytes != len(payload)+7 || sess.outFrames != 1 || len(owned) != len(payload)+7 || cap(owned) != len(owned) {
			t.Fatal("wire allocation not fully charged")
		}
		sess.mu.Unlock()
		payload[0] ^= 0x7f // copied before publish: caller cannot mutate queued ownership.
		if owned[7] != 0x44 || binary.BigEndian.Uint32(owned[1:5]) != 19 {
			t.Fatal("caller alias/header")
		}
		if cancelQueued {
			sess.fail(context.Canceled)
		}
		go sess.writeLoop()
		if !cancelQueued {
			got := make([]byte, len(owned))
			if _, e = io.ReadFull(b, got); e != nil {
				t.Fatal(e)
			}
			if got[0] != cmdPSH || binary.BigEndian.Uint16(got[5:7]) != 4096 || !bytes.Equal(got[7:], bytes.Repeat([]byte{0x44}, 4096)) {
				t.Fatal("bad wire")
			}
		}
		e = <-sent
		if (e != nil) != cancelQueued {
			t.Fatal(e)
		}
		if !cancelQueued {
			sess.fail(context.Canceled)
		}
		<-sess.writerDone
		sess.mu.Lock()
		if sess.outBytes != 0 || sess.outFrames != 0 || frame.wire != nil {
			t.Fatal("budget not reclaimed")
		}
		sess.mu.Unlock()
		if !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("sensitive wire not cleared before release")
		}
		a.Close()
		b.Close()
	}
}

func TestOwnedWireIndependentAuthenticatedUsersSameStreamID(t *testing.T) {
	clients := make([]*testClient, 2)
	payloads := make([][]byte, 2)
	users := []string{"alice", "bob"}
	writes := make(chan error, 2)
	for i, user := range users {
		user := user
		payload := bytes.Repeat([]byte{byte(31 + i)}, 4096)
		payloads[i] = payload
		c := cfg()
		c.Password = "separate-password-" + user
		c.UserID = user
		clients[i] = start(t, c, func(ctx context.Context, st *Stream, r Request) {
			if r.UserID != user {
				t.Errorf("identity crossed: %s/%s", r.UserID, user)
				return
			}
			b := make([]byte, len(payload))
			if _, e := io.ReadFull(st, b); e != nil {
				t.Error(e)
				return
			}
			if !bytes.Equal(b, payload) {
				t.Error("input crossed user/session")
				return
			}
			_, e := st.Write(append([]byte(user+":"), b...))
			writes <- e
		})
		digest := sha256.Sum256([]byte(c.Password))
		auth := append(append([]byte(nil), digest[:]...), 0, 0)
		if e := clients[i].write(append(auth, fixtures(t)["settings_v2"]...)); e != nil {
			t.Fatal(e)
		}
		clients[i].next(t, cmdServerSettings, 0)
	}
	var wg sync.WaitGroup
	for i, client := range clients {
		i, client := i, client
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := client.write(wire(cmdSYN, 1, nil)); e != nil {
				t.Error(e)
				return
			}
			client.next(t, cmdSYNACK, 1)
			data := append(targetBytes(t, Address{"x", 80}), payloads[i]...)
			if e := client.write(wire(cmdPSH, 1, data)); e != nil {
				t.Error(e)
				return
			}
			got := client.next(t, cmdPSH, 1)
			if !bytes.Equal(got.data, append([]byte(users[i]+":"), payloads[i]...)) {
				t.Error("output crossed user/session")
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		select {
		case e := <-writes:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("handler write confirmation missing")
		}
	}
}
