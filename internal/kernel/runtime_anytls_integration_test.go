package kernel

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

// A refused API/stats migration must not revoke a carrier; only the successful
// shared commit may revoke new-stream admission, never its established flows.
func TestRuntimeAtomicAnyTLSRevocationCommit(t *testing.T) {
	for _, blocked := range []string{"api", "stats"} {
		t.Run(blocked, func(t *testing.T) {
			cert, roots := testCert(t)
			in := anyIn(cert)
			in.Listen = reloadPort(t)
			dir := t.TempDir()
			base := socksCfg()
			base.Inbounds = []Inbound{in}
			base.API = &APIOptions{Socket: filepath.Join(dir, "old.sock")}
			base.Stats = &StatsOptions{File: filepath.Join(dir, "old.stats.json")}
			next := base
			s := startReloadable(t, base, &next)
			carrier := atBegin(t, s, roots, 2, in.Listen)
			carrier.SetDeadline(time.Now().Add(10 * time.Second))
			target := echoTCP(t)
			udp := localUDP(t)
			ua := addrFromNet(udp.LocalAddr())
			atOpen(t, carrier, 1, target, []byte("before"))
			atPayload(t, carrier, 1, 6)
			if e := writeAll(carrier, append(atFrame(1, 2, nil), atFrame(2, 2, atUDPHeader(ua, true))...)); e != nil {
				t.Fatal(e)
			}
			atUDPEcho(t, carrier, 2, udp, true, "udp-before")

			next.Inbounds = append([]Inbound(nil), base.Inbounds...)
			options := *in.AnyTLS
			options.Password = "new-fixture-password"
			next.Inbounds[0].AnyTLS = &options
			next.API = &APIOptions{Socket: filepath.Join(dir, "new.sock")}
			next.Stats = &StatsOptions{File: filepath.Join(dir, "new.stats.json")}
			var release func()
			if blocked == "api" {
				ln, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer ln.Close()
				next.API.Listen = ln.Addr().String()
				next.API.Secret = "new-api-fixture-secret"
				release = func() { ln.Close() }
			} else {
				unlock, e := stats.Lock(next.Stats.File)
				if e != nil {
					t.Fatal(e)
				}
				defer unlock()
				release = unlock
			}
			oldAPI := atomicClient(t, base.API.Socket)
			if code, _ := atomicRequest(t, oldAPI, "http://unix/v1/reload", "POST", ""); code != 422 {
				t.Fatalf("candidate %s must refuse, got %d", blocked, code)
			}
			if s.current().id != 1 || s.persistedPath() != base.Stats.File {
				t.Fatal("failed resource preparation changed runtime")
			}
			atTCPEcho(t, carrier, 1, "tcp-after-refusal")
			atUDPEcho(t, carrier, 2, udp, true, "udp-after-refusal")
			atOpen(t, carrier, 3, target, []byte("still-authorized"))
			atPayload(t, carrier, 3, len("still-authorized"))

			release()
			if code, _ := atomicRequest(t, oldAPI, "http://unix/v1/reload", "POST", ""); code != 200 {
				t.Fatalf("shared migration commit: %d", code)
			}
			if s.current().id != 2 || s.persistedPath() != next.Stats.File {
				t.Fatal("successful shared commit not reflected")
			}
			if code, _ := atomicRequest(t, atomicClient(t, next.API.Socket), "http://unix/v1/stats", "GET", ""); code != 200 {
				t.Fatal("new API unavailable", code)
			}
			atOpen(t, carrier, 4, target, []byte("revoked"))
			atRefused(t, carrier, 4)
			if e := writeAll(carrier, append(atFrame(1, 5, nil), atFrame(2, 5, atUDPHeader(ua, true))...)); e != nil {
				t.Fatal(e)
			}
			atRefused(t, carrier, 5)
			atTCPEcho(t, carrier, 1, "tcp-survives-commit")
			atTCPEcho(t, carrier, 3, "precommit-stream-survives")
			atUDPEcho(t, carrier, 2, udp, true, "udp-survives-commit")
			fresh := atTLS(t, in.Listen, roots)
			atAuthenticate(t, fresh, options.Password)
			atOpen(t, fresh, 1, target, []byte("fresh"))
			atPayload(t, fresh, 1, 5)
		})
	}
}
