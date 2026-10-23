package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"
	"errors"
	SS "github.com/shui1iao/Kat/internal/ss"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func udpLockPacket(t *testing.T, codec *SS.Server, key []byte, source netip.AddrPort) *SS.Packet {
	t.Helper()
	salt := bytes.Repeat([]byte{0x63}, 16)
	sub, e := hkdf.Key(sha1.New, key, salt, "ss-subkey", 16)
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(sub)
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	address, _ := (SS.Address{Host: "127.0.0.1", Port: 80}).MarshalBinary()
	wire := append(salt, a.Seal(nil, make([]byte, 12), append(address, []byte("request")...), nil)...)
	p, e := codec.DecodeUDP(wire, source)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestSS2017ReplySocketWaitDoesNotBlockRouting(t *testing.T) {
	key := bytes.Repeat([]byte{0x72}, 16)
	codec, e := SS.NewServer(SS.Config{Method: SS.AES128GCM, Key: key})
	if e != nil {
		t.Fatal(e)
	}
	peer, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	rt := &ssRuntime{codec: codec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{}
	s.cfg.Limits.DialTimeout = Duration(time.Second)
	n := &ssNativeAssociation{a: &udpAssociation{server: s, ctx: ctx}, runtime: rt, listener: &ssUDPListener{socket: socket, runtime: rt}, capability: udpLockPacket(t, codec, key, peer.LocalAddr().(*net.UDPAddr).AddrPort())}
	raw, _ := socket.SyscallConn()
	locked, release, lockDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	go func() { lockDone <- raw.Write(func(uintptr) bool { close(locked); <-release; return true }) }()
	<-locked
	reply := make(chan error, 1)
	go func() { reply <- n.reply(Address{"127.0.0.1", 80}, []byte("answer")) }()
	defer func() {
		unblock()
		socket.Close()
		select {
		case <-lockDone:
		case <-time.After(time.Second):
			t.Error("raw write lock leaked")
		}
	}()
	// Response salt admission establishes EncodeUDP reached completion; reply is
	// now blocked on this socket's real FD write lock, not an arbitrary sleep.
	end := time.Now().Add(time.Second)
	for codec.Stats().Salts2017 < 2 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if codec.Stats().Salts2017 != 2 {
		unblock()
		<-reply
		t.Fatal("reply not encoded")
	}
	acquired := make(chan struct{})
	go func() { rt.mu.Lock(); rt.mu.Unlock(); close(acquired) }()
	select {
	case <-acquired:
	case <-time.After(100 * time.Millisecond):
		unblock()
		<-reply
		t.Fatal("one reply FD blocked listener routing/global association lock")
	}
	unblock()
	if e := <-reply; e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 2048)
	if k, _, e := peer.ReadFromUDPAddrPort(b); e != nil || k < 32 {
		t.Fatal(k, e)
	}
	socket.Close()
	if err := n.reply(Address{"127.0.0.1", 80}, []byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed write error", err)
	}
	rt.mu.Lock()
	rt.mu.Unlock()
	cancel()
	before := codec.Stats().Salts2017
	if e := n.reply(Address{"127.0.0.1", 80}, []byte("late")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if codec.Stats().Salts2017 != before {
		t.Fatal("canceled reply consumed fresh salt")
	}
}
