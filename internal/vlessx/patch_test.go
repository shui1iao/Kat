package vlessx

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	reality "github.com/xtls/reality"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRealityPatchCancellation(t *testing.T) {
	if os.Getenv("KAT_VLESSX_PEER") == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	cert := certFor(t, "front.test")
	decoy := startDecoy(t, cert)
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, e)
	rs, e := NewRealityServer(context.Background(), RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: certRoots(t, cert)})
	must(t, e)
	for _, method := range []string{"context", "owner-close"} {
		t.Run(method, func(t *testing.T) {
			cfg := rs.cfg.Clone()
			cfg.PostHandshakeProfiles = nil
			ln := tcpListen(t)
			defer ln.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := make(chan *ownedConn, 1)
			done := make(chan error, 1)
			go func() {
				c, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				own := &ownedConn{Conn: c, done: make(chan struct{})}
				owner <- own
				defer own.Close()
				s, e := reality.Server(ctx, own, cfg)
				if s != nil {
					s.NetConn().Close()
				}
				done <- e
			}()
			bin, e := filepath.Abs(os.Getenv("KAT_VLESSX_PEER"))
			must(t, e)
			pctx, kill := context.WithTimeout(context.Background(), 8*time.Second)
			defer kill()
			cmd := exec.CommandContext(pctx, bin, "authprobe", ln.Addr().String(), base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), "front.test")
			cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
			out, e := cmd.StdoutPipe()
			must(t, e)
			must(t, cmd.Start())
			ready := make(chan string, 1)
			go func() {
				s := bufio.NewScanner(out)
				if s.Scan() {
					ready <- s.Text()
				} else {
					ready <- ""
				}
			}()
			own := <-owner
			select {
			case line := <-ready:
				if line != "XRAY_AUTH_VERIFIED" {
					kill()
					cmd.Wait()
					t.Fatal(line)
				}
			case <-time.After(3 * time.Second):
				own.Close()
				kill()
				cmd.Wait()
				t.Fatal("auth timeout")
			}
			if method == "context" {
				cancel()
			} else {
				own.Close()
			}
			select {
			case e = <-done:
				if !errors.Is(e, context.Canceled) {
					kill()
					cmd.Wait()
					t.Fatalf("closed/canceled returned %v", e)
				}
			case <-time.After(time.Second):
				kill()
				cmd.Wait()
				t.Fatal("patch failed to release global wait")
			}
			must(t, cmd.Wait())
			t.Log("authenticated missing-profile wait canceled and returned error:", method)
		})
	}
}
func TestRealityPreflightFailureAndValidation(t *testing.T) {
	cert := certFor(t, "front.test")
	decoy := startDecoy(t, cert)
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, e)
	base := RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: certRoots(t, cert)}
	cases := []RealityConfig{}
	c := base
	c.PrivateKey = nil
	cases = append(cases, c)
	c = base
	c.Decoy = netip.MustParseAddrPort("192.0.2.1:443")
	cases = append(cases, c)
	c = base
	c.ShortIDs = nil
	cases = append(cases, c)
	c = base
	c.ServerNames = []string{"bad name"}
	cases = append(cases, c)
	c = base
	c.MinClientVersion = []byte{1, 2}
	cases = append(cases, c)
	c = base
	c.MinClientVersion = []byte{27, 0, 0}
	c.MaxClientVersion = []byte{26, 0, 0}
	cases = append(cases, c)
	for i, c := range cases {
		if _, e := NewRealityServer(context.Background(), c); e == nil {
			t.Fatalf("invalid config accepted %d", i)
		}
	}
	c = base
	c.DecoyRoots = certRoots(t, certFor(t, "other.test"))
	if _, e = NewRealityServer(context.Background(), c); e == nil {
		t.Fatal("untrusted decoy accepted")
	}
	// Slow target: no TLS bytes; both context and socket close release probe.
	ln := tcpListen(t)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	c = base
	c.Decoy = netip.MustParseAddrPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e = NewRealityServer(ctx, c)
	if e == nil || time.Since(start) > time.Second {
		t.Fatal("slow preflight not bounded", e)
	}
	sock := <-accepted
	if sock != nil {
		sock.Close()
	}
}

func TestRealityActiveSessionLimitAndReadDeadline(t *testing.T) {
	if os.Getenv("KAT_VLESSX_PEER") == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	cert := certFor(t, "front.test")
	decoy := startDecoy(t, cert)
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, e)
	rs, e := NewRealityServer(context.Background(), RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: certRoots(t, cert), MaxSessions: 1})
	must(t, e)
	ln := tcpListen(t)
	defer ln.Close()
	sessions := make(chan *Transport, 1)
	errs := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			errs <- e
			return
		}
		tr, e := rs.Accept(context.Background(), c)
		if e != nil {
			errs <- e
			return
		}
		sessions <- tr
	}()
	bin, e := filepath.Abs(os.Getenv("KAT_VLESSX_PEER"))
	must(t, e)
	ctx, kill := context.WithTimeout(context.Background(), 8*time.Second)
	defer kill()
	cmd := exec.CommandContext(ctx, bin, "authprobe", ln.Addr().String(), base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), "front.test")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
	out, e := cmd.StdoutPipe()
	must(t, e)
	must(t, cmd.Start())
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() || scanner.Text() != "XRAY_AUTH_VERIFIED" {
		kill()
		cmd.Wait()
		t.Fatal("peer not verified")
	}
	var tr *Transport
	select {
	case tr = <-sessions:
	case e := <-errs:
		kill()
		cmd.Wait()
		t.Fatal(e)
	case <-time.After(time.Second):
		kill()
		cmd.Wait()
		t.Fatal("Accept stuck")
	}
	defer tr.Close()
	if len(rs.slots) != 1 {
		t.Fatal("active session not counted")
	}
	a, b := net.Pipe()
	defer b.Close()
	if _, e = rs.Accept(context.Background(), a); e != ErrLimit {
		t.Fatal(e)
	}
	must(t, tr.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	var buf [1]byte
	if _, e = tr.Read(buf[:]); e == nil {
		t.Fatal("deadline ignored")
	}
	must(t, tr.Close())
	if len(rs.slots) != 0 {
		t.Fatal("active slot leaked")
	}
	must(t, cmd.Wait())
}
