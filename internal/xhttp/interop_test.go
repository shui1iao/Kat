package xhttp

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

var fixedUUID = []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}

func originalVLESS(authenticated *atomic.Int32, observed chan string) Handler {
	return func(ctx context.Context, st *Stream, m Metadata) error {
		var b [18]byte
		if _, e := io.ReadFull(st, b[:]); e != nil {
			return e
		}
		if b[0] != 0 || !bytes.Equal(b[1:17], fixedUUID) {
			return ErrProtocol
		}
		if b[17] != 0 {
			if _, e := io.CopyN(io.Discard, st, int64(b[17])); e != nil {
				return e
			}
		}
		var head [4]byte
		if _, e := io.ReadFull(st, head[:]); e != nil {
			return e
		}
		if head[0] != 1 {
			return ErrProtocol
		}
		port := binary.BigEndian.Uint16(head[1:3])
		n := 0
		switch head[3] {
		case 1:
			n = 4
		case 3:
			var length [1]byte
			if _, e := io.ReadFull(st, length[:]); e != nil {
				return e
			}
			n = int(length[0])
		case 4:
			n = 16
		default:
			return ErrProtocol
		}
		if _, e := io.CopyN(io.Discard, st, int64(n)); e != nil {
			return e
		}
		authenticated.Add(1)
		observed <- st.Mode()
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
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func socks(c net.Conn, port uint16) error {
	if _, e := c.Write([]byte{5, 1, 0}); e != nil {
		return e
	}
	var method [2]byte
	if _, e := io.ReadFull(c, method[:]); e != nil {
		return e
	}
	if method != [2]byte{5, 0} {
		return ErrProtocol
	}
	_, e := c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	if e != nil {
		return e
	}
	var reply [4]byte
	if _, e = io.ReadFull(c, reply[:]); e != nil {
		return e
	}
	if reply[0] != 5 || reply[1] != 0 {
		return ErrProtocol
	}
	n := 4
	if reply[3] == 4 {
		n = 16
	} else if reply[3] == 3 {
		var b [1]byte
		if _, e = io.ReadFull(c, b[:]); e != nil {
			return e
		}
		n = int(b[0])
	}
	_, e = io.CopyN(io.Discard, c, int64(n+2))
	return e
}
func TestXrayStableTLSAllModes(t *testing.T) {
	binary := os.Getenv("KAT_XHTTP_XRAY")
	if binary == "" {
		t.Skip("set KAT_XHTTP_XRAY to approved stable client")
	}
	for _, proto := range []string{"http/1.1", "h2"} {
		for _, mode := range []string{PacketUp, StreamUp, StreamOne, Auto, "packet-up-no-sse", "stream-up-no-grpc", "packet-up-split", "stream-up-split"} {
			profile := mode
			noSSE := mode == "packet-up-no-sse"
			if noSSE || mode == "packet-up-split" {
				mode = PacketUp
			}
			if mode == "stream-up-no-grpc" || mode == "stream-up-split" {
				mode = StreamUp
			}
			split := profile == "packet-up-split" || profile == "stream-up-split"
			noGRPC := profile == "stream-up-no-grpc"
			t.Run(proto+"/"+profile, func(t *testing.T) {
				var authenticated atomic.Int32
				observed := make(chan string, 4)
				remotes := make(chan string, 4)
				baseHandler := originalVLESS(&authenticated, observed)
				ts := start(t, Config{Mode: Auto, NoSSEHeader: noSSE, IOTimeout: 8 * time.Second, IdleTimeout: 12 * time.Second, PairTimeout: 8 * time.Second}, proto, func(ctx context.Context, st *Stream, m Metadata) error {
					remotes <- m.RemoteAddr
					return baseHandler(ctx, st, m)
				})
				directory := t.TempDir()
				ca := filepath.Join(directory, "ca.pem")
				os.WriteFile(ca, ts.ca, 0600)
				host, portText, _ := net.SplitHostPort(ts.addr)
				var port int
				fmt.Sscan(portText, &port)
				inPort := freePort(t)
				config := map[string]any{"log": map[string]any{"loglevel": "info"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": inPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{map[string]any{"id": testID, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": map[string]any{"serverName": "xh.test", "alpn": []string{proto}, "allowInsecure": false, "disableSystemRoot": true, "minVersion": "1.3", "certificates": []any{map[string]any{"certificateFile": ca, "usage": "verify"}}}, "xhttpSettings": map[string]any{"path": "/xh", "host": "xh.test", "mode": mode, "noSSEHeader": noSSE, "xmux": map[string]any{"maxConnections": 1}}}}}}
				settings := config["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
				xsettings := settings["xhttpSettings"].(map[string]any)
				xsettings["noGRPCHeader"] = noGRPC
				if split {
					xsettings["downloadSettings"] = map[string]any{"address": host, "port": port, "network": "xhttp", "security": "tls", "tlsSettings": settings["tlsSettings"], "xhttpSettings": map[string]any{"path": "/xh", "host": "xh.test", "xmux": map[string]any{"maxConnections": 1}}}
				}
				raw, _ := json.MarshalIndent(config, "", "  ")
				file := filepath.Join(directory, "xray.json")
				os.WriteFile(file, raw, 0600)
				ctx, cancel := context.WithTimeout(context.Background(), 24*time.Second)
				cmd := exec.CommandContext(ctx, "nice", "-n", "10", binary, "run", "-config", file)
				var output bytes.Buffer
				cmd.Stdout = &output
				cmd.Stderr = &output
				if e := cmd.Start(); e != nil {
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
				address := net.JoinHostPort("127.0.0.1", fmt.Sprint(inPort))
				ready := false
				for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
					c, e := net.DialTimeout("tcp", address, 50*time.Millisecond)
					if e == nil {
						c.Close()
						ready = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !ready {
					t.Fatal("Xray not ready")
				}
				for _, first := range []bool{false, true} {
					c, e := net.DialTimeout("tcp", address, time.Second)
					if e != nil {
						t.Fatal(e)
					}
					c.SetDeadline(time.Now().Add(8 * time.Second))
					port := uint16(443)
					if first {
						port = 444
					}
					if e = socks(c, port); e != nil {
						c.Close()
						t.Fatal(e)
					}
					if first {
						p := make([]byte, 7)
						if _, e = io.ReadFull(c, p); e != nil || string(p) != "welcome" {
							c.Close()
							t.Fatal("server-first", e, string(p))
						}
					}
					payload := bytes.Repeat([]byte{0x3e}, 300000)
					sent := make(chan error, 1)
					go func() { sent <- writeAll(c, payload) }()
					got := make([]byte, len(payload))
					_, e = io.ReadFull(c, got)
					we := <-sent
					c.Close()
					if e != nil || we != nil || !bytes.Equal(payload, got) {
						t.Fatal("application bytes", e, we)
					}
				}
				if authenticated.Load() != 2 {
					t.Fatal("missing VLESS authentication", authenticated.Load())
				}
				var selected []string
				for i := 0; i < 2; i++ {
					selected = append(selected, <-observed)
				}
				expected := mode
				if mode == Auto {
					expected = PacketUp
				}
				for _, m := range selected {
					if m != expected {
						t.Fatal("actual mode", m, expected)
					}
				}
				a, b := <-remotes, <-remotes
				if proto == "h2" && a != b {
					t.Fatal("XMUX HTTP2 reuse not observed", a, b)
				}
				t.Logf("XMUX maxConnections=1 download peers %s / %s; explicit downloadSettings=%v noGRPCHeader=%v noSSEHeader=%v", a, b, split, noGRPC, noSSE)
				t.Logf("PASS Xray26.3.27 TLS1.3 verified %s configured=%s selected=%v client-first+server-first 300000B each direction", proto, mode, selected)
			})
		}
	}
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
