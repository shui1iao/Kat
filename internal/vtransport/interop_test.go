package vtransport

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var testUUID = []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}

const testUUIDString = "11111111-1111-4111-8111-111111111111"

// Original TEST-ONLY basic VLESS v0 decoder. Not a production VLESS module,
// never dials targets, rejects wrong UUID/command, echoes only authenticated data.
func basicVLESSEcho(authenticated *atomic.Int32, early *atomic.Int32) Handler {
	return func(ctx context.Context, st *Stream, m Metadata) error {
		var fixed [18]byte
		if _, e := io.ReadFull(st, fixed[:]); e != nil {
			return e
		}
		if fixed[0] != 0 || !bytes.Equal(fixed[1:17], testUUID) {
			return fmt.Errorf("test auth rejected")
		}
		if fixed[17] > 0 {
			if _, e := io.CopyN(io.Discard, st, int64(fixed[17])); e != nil {
				return e
			}
		}
		var tail [4]byte
		if _, e := io.ReadFull(st, tail[:]); e != nil {
			return e
		}
		if tail[0] != 1 {
			return ErrProtocol
		}
		port := binary.BigEndian.Uint16(tail[1:3])
		n := 0
		switch tail[3] {
		case 1:
			n = 4
		case 3:
			var b [1]byte
			if _, e := io.ReadFull(st, b[:]); e != nil {
				return e
			}
			n = int(b[0])
		case 4:
			n = 16
		default:
			return ErrProtocol
		}
		if _, e := io.CopyN(io.Discard, st, int64(n)); e != nil {
			return e
		}
		authenticated.Add(1)
		if m.EarlyDataBytes > 0 {
			early.Add(1)
		}
		if _, e := st.Write([]byte{0, 0}); e != nil {
			return e
		}
		if port == 444 {
			if _, e := st.Write([]byte("welcome")); e != nil {
				return e
			}
		}
		_, e := io.Copy(st, st)
		return e
	}
}
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
func TestXrayStableTLSInterop(t *testing.T) {
	binary := os.Getenv("KAT_VTRANSPORT_XRAY")
	if binary == "" {
		t.Skip("set KAT_VTRANSPORT_XRAY to approved stable Xray binary")
	}
	cases := []struct {
		kind Kind
		mode string
		ed   bool
	}{{WebSocket, "ws", false}, {WebSocket, "ws-ed", true}, {HTTPUpgrade, "upgrade", false}, {HTTPUpgrade, "upgrade-preload", true}, {GRPC, "Tun", false}, {GRPC, "TunMulti", false}}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			var authenticated, early atomic.Int32
			h := start(t, Config{Kind: tc.kind, MaxEarlyData: map[Kind]int{WebSocket: 2048}[tc.kind]}, basicVLESSEcho(&authenticated, &early))
			directory := t.TempDir()
			ca := filepath.Join(directory, "ca.pem")
			if e := os.WriteFile(ca, h.certPEM, 0600); e != nil {
				t.Fatal(e)
			}
			host, portText, e := net.SplitHostPort(h.addr)
			if e != nil {
				t.Fatal(e)
			}
			var port int
			fmt.Sscan(portText, &port)
			inboundPort := freePort(t)
			stream := map[string]any{"network": string(tc.kind), "security": "tls", "tlsSettings": map[string]any{"serverName": "vt.test", "allowInsecure": false, "disableSystemRoot": true, "minVersion": "1.3", "certificates": []any{map[string]any{"certificateFile": ca, "usage": "verify"}}}}
			switch tc.kind {
			case WebSocket:
				path := "/tunnel"
				if tc.ed {
					path += "?ed=1024"
				}
				stream["wsSettings"] = map[string]any{"path": path, "host": "vt.test"}
			case HTTPUpgrade:
				path := "/tunnel"
				if tc.ed {
					path += "?ed=1024"
				}
				stream["httpupgradeSettings"] = map[string]any{"path": path, "host": "vt.test"}
			case GRPC:
				stream["grpcSettings"] = map[string]any{"serviceName": "vt", "multiMode": tc.mode == "TunMulti"}
			}
			config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": inboundPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{map[string]any{"id": testUUIDString, "encryption": "none"}}}}}, "streamSettings": stream}}}
			raw, e := json.MarshalIndent(config, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(directory, "xray.json")
			os.WriteFile(file, raw, 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
			cmd := exec.CommandContext(ctx, "nice", "-n", "10", binary, "run", "-config", file)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if e = cmd.Start(); e != nil {
				cancel()
				t.Fatal(e)
			}
			defer func() {
				cancel()
				_ = cmd.Wait()
				if t.Failed() {
					t.Log(output.String())
				}
			}()
			socks := net.JoinHostPort("127.0.0.1", fmt.Sprint(inboundPort))
			ready := false
			for until := time.Now().Add(4 * time.Second); time.Now().Before(until); {
				c, e := net.DialTimeout("tcp", socks, 50*time.Millisecond)
				if e == nil {
					c.Close()
					ready = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("Xray SOCKS not ready")
			}
			for _, first := range []bool{false, true} {
				c, e := net.DialTimeout("tcp", socks, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				c.SetDeadline(time.Now().Add(6 * time.Second))
				port := 443
				if first {
					port = 444
				}
				if e = socksConnect(c, uint16(port)); e != nil {
					c.Close()
					t.Fatal(e)
				}
				if first {
					p := make([]byte, 7)
					if _, e = io.ReadFull(c, p); e != nil || string(p) != "welcome" {
						c.Close()
						t.Fatal("server-first", string(p), e)
					}
				}
				payload := bytes.Repeat([]byte("original-local-application-data"), 8000)
				written := make(chan error, 1)
				go func() { written <- writeAll(c, payload) }()
				got := make([]byte, len(payload))
				_, e = io.ReadFull(c, got)
				we := <-written
				if e != nil || we != nil || !bytes.Equal(payload, got) {
					c.Close()
					t.Fatal("real TLS application echo mismatch", e, we)
				}
				c.Close()
			}
			if authenticated.Load() != 2 {
				t.Fatal("original VLESS auth not exercised", authenticated.Load())
			}
			if tc.kind == WebSocket && tc.ed && early.Load() < 1 {
				t.Fatal("Xray early-data bytes not observed", early.Load())
			}
			t.Logf("PASS stable Xray 26.3.27 %s TLS1.3 verified CA; basic VLESS auth; client-first + server-first, %dB each direction; early-streams=%d", tc.mode, len("original-local-application-data")*8000, early.Load())
		})
	}
}
func socksConnect(c net.Conn, port uint16) error {
	if e := writeAll(c, []byte{5, 1, 0}); e != nil {
		return e
	}
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return e
	}
	if h != [2]byte{5, 0} {
		return ErrProtocol
	}
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if e := writeAll(c, request); e != nil {
		return e
	}
	var reply [4]byte
	if _, e := io.ReadFull(c, reply[:]); e != nil {
		return e
	}
	if reply[0] != 5 || reply[1] != 0 {
		return ErrProtocol
	}
	n := 0
	switch reply[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var size [1]byte
		if _, e := io.ReadFull(c, size[:]); e != nil {
			return e
		}
		n = int(size[0])
	default:
		return ErrProtocol
	}
	_, e := io.CopyN(io.Discard, c, int64(n+2))
	return e
}
