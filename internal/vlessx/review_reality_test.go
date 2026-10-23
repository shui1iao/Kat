package vlessx

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	reality "github.com/xtls/reality"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestReviewRealityKeyUpdateWithoutCCS(t *testing.T) {
	bin := os.Getenv("KAT_VLESSX_PEER")
	if bin == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	bin, e := filepath.Abs(bin)
	must(t, e)
	cert := certFor(t, "front.test")
	decoy := startDecoy(t, cert)
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, e)
	rs, e := NewRealityServer(context.Background(), RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: certRoots(t, cert)})
	must(t, e)
	for _, omit := range []bool{false, true} {
		t.Run(fmt.Sprintf("omit-ccs-%v", omit), func(t *testing.T) {
			ln := tcpListen(t)
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				raw, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				tr, e := rs.Accept(context.Background(), raw)
				if e != nil {
					done <- e
					return
				}
				defer tr.Close()
				tr.SetDeadline(time.Now().Add(5 * time.Second))
				if secure, ok := tr.secure.(*reality.Conn); ok {
					fmt.Printf("REALITY ACCEPT omit_ccs=%v initial_control_budget=%d\n", omit, secure.MaxUselessRecords)
				}
				p := make([]byte, 5)
				_, e = io.ReadFull(tr, p)
				if e == nil && string(p) != "probe" {
					e = ErrWire
				}
				if e == nil {
					e = writeFull(tr, []byte("reply"))
				}
				done <- e
			}()
			cfg := map[string]any{"Front": ln.Addr().String(), "PublicKey": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), "OmitCCS": omit}
			b, e := json.Marshal(cfg)
			must(t, e)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "review-keyupdate")
			cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
			cmd.Stdin = bytes.NewReader(b)
			out, peerErr := cmd.CombinedOutput()
			serverErr := <-done
			t.Logf("peer output:\n%sserver_error=%v peer_error=%v", out, serverErr, peerErr)
			if serverErr != nil || peerErr != nil {
				t.Fatalf("authenticated REALITY KeyUpdate failed: server=%v peer=%v", serverErr, peerErr)
			}
		})
	}
}
