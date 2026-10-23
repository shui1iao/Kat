package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/sha1"
	A "github.com/shui1iao/Kat/internal/anytls"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestSS2017ParallelReadBudgetReplayAndStop(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	if anyTLSDownLeases*anyTLSDownBytes+ss2017ExtraReadBuffers*65535+A.OwnedMetadataReservedBytes > 16*65528 {
		t.Fatal("combined process wire budget grew")
	}
	prior := len(ss2017ReadSlots)
	target := localUDP(t)
	in := Inbound{Protocol: "shadowsocks", SS: &SSOptions{Method: "aes-128-gcm", Password: "parallel-fixture"}}
	s := startTest(t, in, nil)
	waitFor(t, func() bool { return len(ss2017ReadSlots) > prior })
	client := localUDP(t)
	endpoint, e := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	if e != nil {
		t.Fatal(e)
	}
	key := md5.Sum([]byte("parallel-fixture"))
	salt := bytes.Repeat([]byte{0x76}, 16)
	sub, e := hkdf.Key(sha1.New, key[:], salt, "ss-subkey", 16)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := aes.NewCipher(sub)
	a, _ := cipher.NewGCM(block)
	plain := append(peerAddr(addrFromNet(target.LocalAddr()), false), []byte("once")...)
	wire := append(salt, a.Seal(nil, make([]byte, 12), plain, nil)...)
	for i := 0; i < 8; i++ {
		if _, e := client.WriteToUDP(wire, endpoint); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := recvUDP(t, target)
	if string(b) != "once" {
		t.Fatal("bad forwarded payload")
	}
	target.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buffer := make([]byte, 64)
	if _, _, e := target.ReadFromUDP(buffer); e == nil {
		t.Fatal("parallel readers bypassed exact replay protection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s.Close(ctx)
	if len(ss2017ReadSlots) != prior {
		t.Fatal("extra reader token leaked after real Server.Close")
	}
}
