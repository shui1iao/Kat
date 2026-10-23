package vlessx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"

	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var testID = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

const testUUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func certRoots(t *testing.T, cert tls.Certificate) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	c, e := x509.ParseCertificate(cert.Certificate[0])
	must(t, e)
	roots.AddCert(c)
	return roots
}
func certPEM(cert tls.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
}
func targetAddr(t *testing.T, addr string) Address {
	t.Helper()
	h, p, e := net.SplitHostPort(addr)
	must(t, e)
	var port int
	_, e = fmt.Sscan(p, &port)
	must(t, e)
	return Address{h, uint16(port)}
}
func tcpListen(t *testing.T) net.Listener {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	return l
}
func certFor(t *testing.T, names ...string) tls.Certificate {
	// localCert generated in the diagnostic helper, with sufficient certificate
	// size for REALITY synthetic Certificate handshake; replace SANs by regenerating.
	return makeCertificate(t, names)
}

type peerProc struct {
	cmd  *exec.Cmd
	port int
	logs *bytes.Buffer
}

func startPeer(t *testing.T, front string, mode, flow string, cert tls.Certificate, pub []byte, mutate func(map[string]any)) *peerProc {
	t.Helper()
	bin := os.Getenv("KAT_VLESSX_PEER")
	if bin == "" {
		t.Skip("KAT_VLESSX_PEER not set")
	}
	bin, e := filepath.Abs(bin)
	must(t, e)
	reserve := tcpListen(t)
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	host, p, e := net.SplitHostPort(front)
	must(t, e)
	var serverPort int
	fmt.Sscan(p, &serverPort)
	stream := map[string]any{"network": "raw", "security": "tls", "tlsSettings": map[string]any{"serverName": "front.test", "allowInsecure": false, "certificates": []any{map[string]any{"certificate": strings.Split(strings.TrimSpace(certPEM(cert)), "\n"), "usage": "verify"}}}}
	if mode == "reality" {
		stream = map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "front.test", "fingerprint": "chrome", "publicKey": base64.RawURLEncoding.EncodeToString(pub), "shortId": "01", "spiderX": "/"}}
	}
	if mutate != nil {
		mutate(stream)
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "error"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": serverPort, "users": []any{map[string]any{"id": testUUID, "encryption": "none", "flow": flow}}}}}, "streamSettings": stream}}}
	b, e := json.Marshal(cfg)
	must(t, e)
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(b)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
	logs := new(bytes.Buffer)
	cmd.Stderr = logs
	out, e := cmd.StdoutPipe()
	must(t, e)
	must(t, cmd.Start())
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(out)
		announced := false
		for s.Scan() {
			fmt.Println("XRAY LOG:", s.Text())
			if s.Text() == "XRAY_READY" && !announced {
				ready <- true
				announced = true
			}
		}
		if !announced {
			ready <- false
		}
	}()
	select {
	case ok := <-ready:
		if !ok {
			cmd.Wait()
			t.Fatalf("peer failed: %s", logs)
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("peer startup timeout")
	}
	pp := &peerProc{cmd: cmd, port: port, logs: logs}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		t.Logf("Xray peer stderr: %s", logs)
	})
	return pp
}
func socksConnect(t *testing.T, p *peerProc, a Address) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), time.Second)
	must(t, e)
	c.SetDeadline(time.Now().Add(8 * time.Second))
	must(t, writeFull(c, []byte{5, 1, 0}))
	var hello [2]byte
	_, e = io.ReadFull(c, hello[:])
	must(t, e)
	if hello != [2]byte{5, 0} {
		t.Fatal(hello)
	}
	addr, e := encodeAddress(a)
	must(t, e) // SOCKS uses address then port, and types1/3/4.
	typ := addr[2]
	if typ == 2 {
		typ = 3
	} else if typ == 3 {
		typ = 4
	}
	b := []byte{5, 1, 0, typ}
	b = append(b, addr[3:]...)
	b = append(b, addr[:2]...)
	must(t, writeFull(c, b))
	var reply [4]byte
	_, e = io.ReadFull(c, reply[:])
	must(t, e)
	if reply[1] != 0 {
		c.Close()
		t.Fatalf("SOCKS reply %v", reply)
	}
	n := 4
	if reply[3] == 4 {
		n = 16
	} else if reply[3] == 3 {
		var size [1]byte
		io.ReadFull(c, size[:])
		n = int(size[0])
	}
	_, e = io.CopyN(io.Discard, c, int64(n+2))
	must(t, e)
	return c
}

type testFront struct {
	ln                net.Listener
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	raw               sync.Map
	errs              chan error
	readRaw, writeRaw atomic.Int32
	requests          atomic.Int32
	udp               atomic.Int32
}

func startFront(t *testing.T, mode, expectedFlow string, cert tls.Certificate, rs *RealityServer, udpHook ...func(Datagram) (Address, []byte, error)) *testFront {
	t.Helper()
	f := &testFront{ln: tcpListen(t), errs: make(chan error, 32)}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, e := f.ln.Accept()
			if e != nil {
				return
			}
			f.raw.Store(c, true)
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer f.raw.Delete(c)
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var tr *Transport
				var e error
				if mode == "reality" {
					tr, e = rs.Accept(f.ctx, c)
				} else {
					tr, e = AcceptTLS(f.ctx, c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
				}
				if e != nil {
					if f.ctx.Err() == nil {
						f.errs <- e
					}
					return
				}
				defer tr.Close()
				tr.SetDeadline(time.Now().Add(10 * time.Second))
				q, e := ReadRequest(tr, func(q Request) bool {
					return q.UUID == testID && (q.Flow == expectedFlow || (q.Command == 3 && expectedFlow == VisionFlow && q.Flow == ""))
				})
				if e != nil {
					f.errs <- e
					return
				}
				f.requests.Add(1)
				if e = WriteResponse(tr); e != nil {
					f.errs <- e
					return
				}
				var stream io.ReadWriteCloser = tr
				var vv *Vision
				if q.Flow == VisionFlow {
					vv, e = NewVision(tr, q.UUID)
					if e != nil {
						f.errs <- e
						return
					}
					stream = vv
					defer func() {
						r, w := vv.DirectState()
						if r {
							f.readRaw.Add(1)
						}
						if w {
							f.writeRaw.Add(1)
						}
					}()
				}
				if q.Command == 3 {
					mux, e := NewMux(stream, 8)
					if e != nil {
						f.errs <- e
						return
					}
					defer mux.Close()
					for {
						d, e := mux.ReadDatagram()
						if e != nil {
							return
						}
						if len(udpHook) > 0 {
							source, p, err := udpHook[0](d)
							if err != nil {
								f.errs <- err
								return
							}
							f.udp.Add(1)
							if err = mux.Reply(d, source, p); err != nil {
								return
							}
							continue
						}
						addr, e := netip.ParseAddr(d.Target.Host)
						if e != nil || !addr.IsLoopback() {
							f.errs <- ErrState
							return
						}
						u, e := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, d.Target.Port)))
						if e != nil {
							f.errs <- e
							return
						}
						u.SetDeadline(time.Now().Add(time.Second))
						_, e = u.Write(d.Payload)
						buf := make([]byte, 8192)
						n, source, e := u.ReadFromUDPAddrPort(buf)
						u.Close()
						if e != nil {
							f.errs <- e
							return
						}
						f.udp.Add(1)
						if e = mux.Reply(d, Address{source.Addr().String(), source.Port()}, buf[:n]); e != nil {
							return
						}
					}
				}
				if q.Command != 1 {
					f.errs <- ErrUnsupported
					return
				}
				addr, e := netip.ParseAddr(q.Target.Host)
				if e != nil || !addr.IsLoopback() {
					f.errs <- ErrState
					return
				}
				up, e := net.DialTimeout("tcp", q.Target.String(), time.Second)
				if e != nil {
					f.errs <- e
					return
				}
				defer up.Close()
				up.SetDeadline(time.Now().Add(10 * time.Second))
				done := make(chan error, 1)
				go func() { _, e := io.Copy(up, stream); up.(*net.TCPConn).CloseWrite(); done <- e }()
				_, downErr := io.Copy(stream, up)
				if w, ok := stream.(interface{ CloseWrite() error }); ok {
					w.CloseWrite()
				}
				up.Close()
				stream.Close()
				<-done
				_ = downErr
			}()
		}
	}()
	t.Cleanup(func() {
		f.cancel()
		f.ln.Close()
		f.raw.Range(func(c, v any) bool { c.(net.Conn).Close(); return true })
		f.wg.Wait()
		close(f.errs)
		for e := range f.errs {
			t.Log("front error:", e)
		}
		t.Logf("requests=%d UDP=%d direct read/write=%d/%d", f.requests.Load(), f.udp.Load(), f.readRaw.Load(), f.writeRaw.Load())
	})
	return f
}
func qFlowUDP(got, expected string) bool { return expected == VisionFlow && got == "" }
func httpTarget(t *testing.T, secure bool, version uint16, cert tls.Certificate) (Address, []byte) {
	t.Helper()
	payload := bytes.Repeat([]byte("0123456789abcdefghijklmnopqrstuvwxyz"), 32768)
	ln := tcpListen(t)
	var l net.Listener = ln
	if secure {
		l = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upload, e := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if e != nil || !bytes.Equal(upload, payload) {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.Header().Set("Connection", "close")
		w.Write(payload)
	}), ReadHeaderTimeout: 3 * time.Second}
	done := make(chan struct{})
	go func() { srv.Serve(l); close(done) }()
	t.Cleanup(func() { srv.Close(); ln.Close(); <-done })
	return targetAddr(t, ln.Addr().String()), payload
}
func httpRound(t *testing.T, p *peerProc, a Address, payload []byte, secure bool, version uint16, roots *x509.CertPool) {
	t.Helper()
	raw := socksConnect(t, p, a)
	defer raw.Close()
	var c net.Conn = raw
	if secure {
		s := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "inner.test", MinVersion: version, MaxVersion: version})
		must(t, s.Handshake())
		c = s
	}
	must(t, writeFull(c, []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: inner.test\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload)))))
	if secure && version == tls.VersionTLS13 {
		time.Sleep(20 * time.Millisecond)
		must(t, writeFull(c, payload[:1024]))
		time.Sleep(20 * time.Millisecond)
		must(t, writeFull(c, payload[1024:]))
	} else {
		must(t, writeFull(c, payload))
	}
	resp, e := http.ReadResponse(bufio.NewReader(c), nil)
	must(t, e)
	got, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	must(t, e)
	resp.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("HTTP mismatch got=%d want=%d", len(got), len(payload))
	}
	t.Logf("HTTP secure=%v innerTLS=%x verified bytes=%d", secure, version, len(got))
}
func TestXrayCombinations(t *testing.T) {
	if os.Getenv("KAT_VLESSX_PEER") == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	cert := certFor(t, "front.test", "inner.test")
	roots := certRoots(t, cert)
	for _, combo := range []struct{ mode, flow string }{{"tls", VisionFlow}, {"reality", ""}, {"reality", VisionFlow}} {
		t.Run(combo.mode+"/"+combo.flow, func(t *testing.T) {
			var rs *RealityServer
			var pub []byte
			if combo.mode == "reality" {
				decoy := startDecoy(t, cert)
				priv, e := ecdh.X25519().GenerateKey(rand.Reader)
				must(t, e)
				pub = priv.PublicKey().Bytes()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				rs, e = NewRealityServer(ctx, RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: roots})
				must(t, e)
			}
			front := startFront(t, combo.mode, combo.flow, cert, rs)
			peer := startPeer(t, front.ln.Addr().String(), combo.mode, combo.flow, cert, pub, nil)
			for _, version := range []uint16{0, tls.VersionTLS13, tls.VersionTLS12} {
				target, payload := httpTarget(t, version != 0, version, cert)
				httpRound(t, peer, target, payload, version != 0, version, roots)
			}
			serverFirstRound(t, peer)
			wireHalfcloseRound(t, front, combo.mode, combo.flow, cert, pub)
			xudpRound(t, peer, front)
			if combo.flow == VisionFlow {
				if front.readRaw.Load() < 1 || front.writeRaw.Load() < 1 {
					t.Fatalf("both Vision directions must switch at least once: %d/%d", front.readRaw.Load(), front.writeRaw.Load())
				}
			}
		})
	}
}
func serverFirstRound(t *testing.T, p *peerProc) {
	t.Helper()
	ln := tcpListen(t)
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(8 * time.Second))
		if e = writeFull(c, []byte("greeting-before-client\n")); e != nil {
			done <- e
			return
		}
		b := make([]byte, len("half-close-payload"))
		_, e = io.ReadFull(c, b)
		if e == nil {
			e = writeFull(c, append([]byte("reply:"), b...))
		}
		done <- e
	}()
	raw := socksConnect(t, p, targetAddr(t, ln.Addr().String()))
	defer raw.Close()
	r := bufio.NewReader(raw)
	line, e := r.ReadString(10)
	must(t, e)
	if line != "greeting-before-client\n" {
		t.Fatal(line)
	}
	must(t, writeFull(raw, []byte("half-close-payload")))
	must(t, raw.(*net.TCPConn).CloseWrite())
	got, e := io.ReadAll(r)
	must(t, e)
	if string(got) != "reply:half-close-payload" {
		t.Fatalf("half close got %q", got)
	}
	must(t, <-done)
	t.Log("Xray SOCKS server-first PASS; transport half-close tested by explicit Xray wire peer")
}
func startDecoy(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln := tcpListen(t)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var conns sync.Map
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			conns.Store(c, true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conns.Delete(c)
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
				if s.HandshakeContext(ctx) == nil {
					io.Copy(io.Discard, s)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		conns.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	return ln.Addr().String()
}

var _ = hex.EncodeToString

func wireHalfcloseRound(t *testing.T, front *testFront, mode, flow string, cert tls.Certificate, pub []byte) {
	t.Helper()
	ln := tcpListen(t)
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(8 * time.Second))
		e = writeFull(c, []byte("greeting-before-client\n"))
		if e != nil {
			done <- e
			return
		}
		b, e := io.ReadAll(io.LimitReader(c, 1024))
		if e == nil {
			e = writeFull(c, append([]byte("reply:"), b...))
		}
		done <- e
	}()
	cfg := map[string]string{"Front": front.ln.Addr().String(), "Target": ln.Addr().String(), "Mode": mode, "Flow": flow, "Certificate": certPEM(cert), "PublicKey": base64.RawURLEncoding.EncodeToString(pub)}
	b, e := json.Marshal(cfg)
	must(t, e)
	bin, e := filepath.Abs(os.Getenv("KAT_VLESSX_PEER"))
	must(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "halfclose")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
	cmd.Stdin = bytes.NewReader(b)
	out, e := cmd.CombinedOutput()
	t.Logf("wire peer: %s", out)
	must(t, e)
	must(t, <-done)
}
func udpTarget(t *testing.T) Address {
	t.Helper()
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, e)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [8192]byte
		for {
			n, a, e := c.ReadFromUDP(b[:])
			if e != nil {
				return
			}
			c.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return targetAddr(t, c.LocalAddr().String())
}
func xudpRound(t *testing.T, p *peerProc, f *testFront) {
	t.Helper()
	control, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), time.Second)
	must(t, e)
	defer control.Close()
	control.SetDeadline(time.Now().Add(5 * time.Second))
	must(t, writeFull(control, []byte{5, 1, 0}))
	var h [2]byte
	_, e = io.ReadFull(control, h[:])
	must(t, e)
	must(t, writeFull(control, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}))
	var reply [10]byte
	_, e = io.ReadFull(control, reply[:])
	must(t, e)
	if reply[1] != 0 || reply[3] != 1 {
		t.Fatal(reply)
	}
	relay := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{reply[4], reply[5], reply[6], reply[7]}), uint16(reply[8])<<8|uint16(reply[9])))
	conn, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, e)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for i, a := range []Address{udpTarget(t), udpTarget(t)} {
		data := bytes.Repeat([]byte{byte(0x40 + i)}, 399+i*500)
		addr, e := encodeAddress(a)
		must(t, e)
		socks := []byte{0, 0, 0, 1}
		socks = append(socks, addr[3:]...)
		socks = append(socks, addr[:2]...)
		socks = append(socks, data...)
		_, e = conn.WriteToUDP(socks, relay)
		must(t, e)
		var buf [8192]byte
		n, _, e := conn.ReadFromUDP(buf[:])
		must(t, e)
		if n < 10 || buf[3] != 1 || !bytes.Equal(buf[10:n], data) {
			t.Fatalf("UDP mismatch n=%d", n)
		}
		if !bytes.Equal(buf[4:8], addr[3:]) || buf[8] != addr[0] || buf[9] != addr[1] {
			t.Fatal("UDP source target mismatch")
		}
		t.Logf("Xray XUDP destination=%s payload=%d", a.String(), len(data))
	}
}

func TestSingVmessXUDP(t *testing.T) {
	bin := os.Getenv("KAT_VLESSX_SV_PEER")
	if bin == "" {
		t.Skip("KAT_VLESSX_SV_PEER required")
	}
	path, e := filepath.Abs(bin)
	must(t, e)
	cert := certFor(t, "front.test")
	front := startFront(t, "tls", "", cert, nil)
	a, b := udpTarget(t), udpTarget(t)
	cfg := map[string]any{"Front": front.ln.Addr().String(), "Certificate": certPEM(cert), "Targets": []string{a.String(), b.String()}}
	input, e := json.Marshal(cfg)
	must(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
	out, e := cmd.CombinedOutput()
	t.Logf("sing-vmess independent peer: %s", out)
	must(t, e)
	if front.udp.Load() != 2 {
		t.Fatal(front.udp.Load())
	}
}
func TestXrayAuthenticationNegatives(t *testing.T) {
	if os.Getenv("KAT_VLESSX_PEER") == "" {
		t.Skip("KAT_VLESSX_PEER required")
	}
	cert := certFor(t, "front.test")
	decoy := startDecoy(t, cert)
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, e)
	rs, e := NewRealityServer(context.Background(), RealityConfig{PrivateKey: priv.Bytes(), ShortIDs: [][8]byte{{1}}, ServerNames: []string{"front.test"}, Decoy: netip.MustParseAddrPort(decoy), DecoyRoots: certRoots(t, cert)})
	must(t, e)
	tests := []struct {
		name, mode string
		mutate     func(map[string]any)
	}{
		{"tls-wrong-sni", "tls", func(s map[string]any) { s["tlsSettings"].(map[string]any)["serverName"] = "wrong.test" }},
		{"tls-untrusted-root", "tls", func(s map[string]any) {
			c := certFor(t, "other.test")
			s["tlsSettings"].(map[string]any)["certificates"] = []any{map[string]any{"certificate": strings.Split(strings.TrimSpace(certPEM(c)), "\n"), "usage": "verify"}}
		}},
		{"reality-wrong-public-key", "reality", func(s map[string]any) {
			other, e := ecdh.X25519().GenerateKey(rand.Reader)
			must(t, e)
			s["realitySettings"].(map[string]any)["publicKey"] = base64.RawURLEncoding.EncodeToString(other.PublicKey().Bytes())
		}},
		{"reality-wrong-sni", "reality", func(s map[string]any) { s["realitySettings"].(map[string]any)["serverName"] = "wrong.test" }},
		{"reality-wrong-shortid", "reality", func(s map[string]any) { s["realitySettings"].(map[string]any)["shortId"] = "02" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			front := startFront(t, tt.mode, VisionFlow, cert, rs)
			p := startPeer(t, front.ln.Addr().String(), tt.mode, VisionFlow, cert, priv.PublicKey().Bytes(), tt.mutate)
			c := socksConnect(t, p, Address{"127.0.0.1", 1})
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Write([]byte("bad authentication must not dial target"))
			var b [1]byte
			_, e := c.Read(b[:])
			if e == nil {
				t.Fatal("authentication unexpectedly returned data")
			}
			if front.requests.Load() != 0 {
				t.Fatal("unauthenticated request exposed")
			}
			t.Log("authentication rejected; no VLESS request exposed")
		})
	}
}
