package kernel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional independent upstream peer. The server binary never imports or calls Xray.
// Set KAT_XRAY to an explicitly built, pinned, test-only executable.
func TestXrayIndependentPeer(t *testing.T) {
	binary := os.Getenv("KAT_XRAY")
	if binary == "" {
		t.Skip("set KAT_XRAY for independent Xray interoperability")
	}
	cert, _ := testCert(t)
	for _, tc := range []struct {
		p      string
		tls    bool
		method string
	}{{"trojan", true, ""}, {"vless", false, ""}, {"vless", true, ""}, {"shadowsocks", false, "aes-128-gcm"}, {"shadowsocks", false, "aes-256-gcm"}, {"shadowsocks", false, "chacha20-ietf-poly1305"}, {"shadowsocks", false, "2022-blake3-aes-128-gcm"}, {"shadowsocks", false, "2022-blake3-aes-256-gcm"}, {"shadowsocks", false, "2022-blake3-chacha20-poly1305"}} {
		t.Run(fmt.Sprintf("%s-%s-tls%v", tc.p, tc.method, tc.tls), func(t *testing.T) {
			var cfg *TLSConfig
			if tc.tls {
				cfg = cert
			}
			in := inFor(tc.p, cfg)
			password := "xray-ss-core-fixture"
			if tc.p == "shadowsocks" {
				in.SS = &SSOptions{Method: tc.method, Password: password}
				if strings.HasPrefix(tc.method, "2022-") {
					size := 32
					if strings.Contains(tc.method, "128") {
						size = 16
					}
					password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, size))
					in.SS.Password = ""
					in.SS.Key = password
				}
			}
			s := startTest(t, in, nil)
			probe, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := probe.Addr().(*net.TCPAddr).Port
			probe.Close()
			upstream := s.Addresses()[0].(*net.TCPAddr)
			user := map[string]any{"id": testUUID, "encryption": "none", "flow": ""}
			settings := map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": upstream.Port, "users": []any{user}}}}
			if tc.p == "trojan" {
				settings = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": upstream.Port, "password": "test-password"}}}
			}
			if tc.p == "shadowsocks" {
				settings = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": upstream.Port, "method": tc.method, "password": password}}}
			}
			stream := map[string]any{"network": "tcp", "security": "none"}
			if tc.tls {
				stream["security"] = "tls"
				stream["tlsSettings"] = map[string]any{"serverName": "localhost", "allowInsecure": false, "disableSystemRoot": true, "certificates": []any{map[string]any{"certificateFile": cert.Cert, "usage": "verify"}}}
			}
			config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": port, "settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}}}, "outbounds": []any{map[string]any{"protocol": tc.p, "settings": settings, "streamSettings": stream, "mux": map[string]any{"enabled": false}}}}
			b, _ := json.Marshal(config)
			dir := t.TempDir()
			path := filepath.Join(dir, "peer.json")
			os.WriteFile(path, b, 0600)
			log, e := os.Create(filepath.Join(dir, "peer.log"))
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(binary, "run", "-config", path)
			cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true", "xray.cone.disabled=true")
			cmd.Stdout = log
			cmd.Stderr = log
			if e = cmd.Start(); e != nil {
				log.Close()
				t.Fatal(e)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); log.Close() })
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			ready := false
			for range 100 {
				c, e := net.DialTimeout("tcp", addr, 20*time.Millisecond)
				if e == nil {
					c.Close()
					ready = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("independent peer did not bind loopback SOCKS endpoint")
			}
			target := echoTCP(t)
			c, e := net.DialTimeout("tcp", addr, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			socksGreeting(t, c, false, "")
			writeAll(c, peerHeader("socks5", 1, target))
			peerResponse(t, c, "socks5")
			payload := []byte("independent-xray-tcp")
			writeAll(c, payload)
			got, e := readN(c, len(payload))
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatalf("Xray TCP: %q %v", got, e)
			}
			c.Close()
			uTarget, _ := echoUDP(t)
			control, e := net.DialTimeout("tcp", addr, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer control.Close()
			control.SetDeadline(time.Now().Add(3 * time.Second))
			socksGreeting(t, control, false, "")
			writeAll(control, peerHeader("socks5", 3, Address{"0.0.0.0", 0}))
			relayAddr := peerResponse(t, control, "socks5")
			relay, e := net.ResolveUDPAddr("udp", relayAddr.String())
			if e != nil {
				t.Fatal(e)
			}
			u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			socksUDPSend(t, u, relay, uTarget, []byte("independent-xray-udp"), 0)
			if got := socksUDPRead(t, u); string(got) != "independent-xray-udp" {
				t.Fatalf("Xray UDP %q", got)
			}
		})
	}
}
