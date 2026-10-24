package kernel

// Real-process end-to-end tests of the routing core. They are skipped unless
//
//	KAT_E2E_KAT=<kat binary under test (the candidate)>
//	KAT_INTEROP_SINGBOX=<sing-box 1.14.3>
//
// are set. Runs that start real processes should not overlap each other.
// KAT_E2E_DIR (optional) keeps every generated config and raw process log.
// Everything listens on loopback; DNS for *.e2e.test is a test server on
// 127.0.0.1 used by the entry Kat, the upstream Kat processes and sing-box.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
)

// Test-only credentials (generated for these loopback fixtures only).
var (
	e2eEntryKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	e2eSBKey    = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 16))
	e2eKatKey   = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 16))
)

const (
	e2eTrojanPass = "e2e-trojan-pass"
	e2eAnyTLSPass = "e2e-anytls-pass"
	e2eMethod     = "2022-blake3-aes-128-gcm"
)

type e2eWorld struct {
	t         *testing.T
	dir       string
	kat, sb   string
	logMu     sync.Mutex
	log       *os.File
	dns       *dnsFixture
	cert      string
	key       string
	pin       string
	oomBase   int64
	procs     []*e2eProc
	echoTCP   map[string]uint16 // by IP
	echoUDP   uint16
	httpPort  int
	httpCount atomic.Int64
}

func e2eSetup(t *testing.T) *e2eWorld {
	kat, sb := os.Getenv("KAT_E2E_KAT"), os.Getenv("KAT_INTEROP_SINGBOX")
	if kat == "" || sb == "" {
		t.Skip("set KAT_E2E_KAT and KAT_INTEROP_SINGBOX to run real-process E2E tests")
	}
	base := os.Getenv("KAT_E2E_DIR")
	if base == "" {
		base = t.TempDir()
	}
	dir := filepath.Join(base, strings.ReplaceAll(t.Name(), "/", "_"))
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	lf, e := os.Create(filepath.Join(dir, "test.log"))
	if e != nil {
		t.Fatal(e)
	}
	w := &e2eWorld{t: t, dir: dir, kat: kat, sb: sb, log: lf, echoTCP: map[string]uint16{}}
	w.oomBase = -1
	w.mem("start")
	t.Cleanup(func() {
		for i := len(w.procs) - 1; i >= 0; i-- {
			w.procs[i].kill()
		}
		w.mem("end")
		lf.Close()
	})
	w.dns = newDNSFixture(t, func(q []byte) []byte {
		var m dnsmessage.Message
		if m.Unpack(q) != nil || len(m.Questions) != 1 {
			return nil
		}
		if strings.HasSuffix(m.Questions[0].Name.String(), ".e2e.test.") {
			return dnsReply(q, []string{"127.0.0.1"}, 5)
		}
		return dnsReply(q, nil, 5)
	})
	w.certs()
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"} {
		w.echoTCP[ip] = w.tcpEcho(ip)
	}
	w.echoUDP = w.udpEcho()
	w.httpServer()
	w.logf("dir=%s kat=%s sing-box=%s dns=%s", dir, kat, sb, w.dns.udp.LocalAddr())
	return w
}

func (w *e2eWorld) logf(format string, a ...any) {
	w.t.Helper()
	line := fmt.Sprintf(format, a...)
	w.logMu.Lock()
	fmt.Fprintf(w.log, "%s %s\n", time.Now().Format("15:04:05.000"), line)
	w.logMu.Unlock()
	w.t.Log(line)
}

// mem records MemAvailable and oom_kill; a low-memory or new OOM condition
// stops the test (common-agent-rules: < 1GiB or oom_kill increase).
func (w *e2eWorld) mem(stage string) {
	avail := int64(-1)
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "MemAvailable:") {
				f := strings.Fields(l)
				if len(f) >= 2 {
					avail, _ = strconv.ParseInt(f[1], 10, 64)
				}
			}
		}
	}
	oom := int64(-1)
	if b, e := os.ReadFile("/proc/vmstat"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "oom_kill ") {
				oom, _ = strconv.ParseInt(strings.TrimPrefix(l, "oom_kill "), 10, 64)
			}
		}
	}
	w.logf("resource stage=%s MemAvailable_kB=%d oom_kill=%d", stage, avail, oom)
	if w.oomBase < 0 {
		w.oomBase = oom
	}
	if avail >= 0 && avail < 1<<20 {
		w.t.Fatalf("MemAvailable %d kB < 1GiB: stopping", avail)
	}
	if oom > w.oomBase {
		w.t.Fatalf("oom_kill increased %d -> %d: stopping", w.oomBase, oom)
	}
}

func (w *e2eWorld) certs() {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		w.t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "kat-e2e-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		w.t.Fatal(e)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	w.cert, w.key = filepath.Join(w.dir, "test-cert.pem"), filepath.Join(w.dir, "test-key.pem")
	os.WriteFile(w.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(w.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600)
	sum := sha256.Sum256(der)
	w.pin = hex.EncodeToString(sum[:])
}

func e2eFreePort(t *testing.T) int {
	for range 100 {
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		u, e := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(p))
		ln.Close()
		if e == nil {
			u.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func (w *e2eWorld) tcpEcho(ip string) uint16 {
	ln, e := net.Listen("tcp4", ip+":0")
	if e != nil {
		w.t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	w.t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func (w *e2eWorld) udpEcho() uint16 {
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		w.t.Fatal(e)
	}
	done := make(chan struct{})
	w.t.Cleanup(func() { c.Close(); <-done })
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			c.WriteTo(b[:n], a)
		}
	}()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// httpServer is the probe target of the automatic groups (loopback only).
func (w *e2eWorld) httpServer() {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		w.t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.httpCount.Add(1)
		rw.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(ln)
	w.t.Cleanup(func() { srv.Close() })
	w.httpPort = ln.Addr().(*net.TCPAddr).Port
}

// ---- counting / delaying forwarder in front of an upstream server ----

type e2eFwd struct {
	name     string
	port     int
	target   string
	delay    time.Duration
	tcp, udp atomic.Int64
	ln       net.Listener
	pc       *net.UDPConn
	mu       sync.Mutex
	conns    map[io.Closer]bool
	wg       sync.WaitGroup
}

func (w *e2eWorld) forwarder(name string, target int, delay time.Duration) *e2eFwd {
	f := &e2eFwd{name: name, target: "127.0.0.1:" + strconv.Itoa(target), delay: delay, conns: map[io.Closer]bool{}}
	for range 100 {
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			w.t.Fatal(e)
		}
		pc, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.Addr().(*net.TCPAddr).Port})
		if e != nil {
			ln.Close()
			continue
		}
		f.ln, f.pc, f.port = ln, pc, ln.Addr().(*net.TCPAddr).Port
		break
	}
	if f.ln == nil {
		w.t.Fatal("no forwarder port")
	}
	w.t.Cleanup(f.close)
	f.wg.Add(2)
	go f.serveTCP()
	go f.serveUDP()
	w.logf("forwarder %s 127.0.0.1:%d -> %s delay=%s", name, f.port, f.target, delay)
	return f
}
func (f *e2eFwd) track(c io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conns == nil {
		c.Close()
		return false
	}
	f.conns[c] = true
	return true
}
func (f *e2eFwd) close() {
	f.ln.Close()
	f.pc.Close()
	f.mu.Lock()
	for c := range f.conns {
		c.Close()
	}
	f.conns = nil
	f.mu.Unlock()
	f.wg.Wait()
}
func (f *e2eFwd) serveTCP() {
	defer f.wg.Done()
	for {
		c, e := f.ln.Accept()
		if e != nil {
			return
		}
		f.tcp.Add(1)
		if !f.track(c) {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer c.Close()
			if f.delay > 0 {
				time.Sleep(f.delay)
			}
			u, e := net.DialTimeout("tcp", f.target, 5*time.Second)
			if e != nil {
				return
			}
			if !f.track(u) {
				return
			}
			defer u.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(u, c); u.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(c, u); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}
func (f *e2eFwd) serveUDP() {
	defer f.wg.Done()
	peers := map[netip.AddrPort]*net.UDPConn{}
	b := make([]byte, 65535)
	for {
		n, src, e := f.pc.ReadFromUDPAddrPort(b)
		if e != nil {
			return
		}
		f.udp.Add(1)
		u := peers[src]
		if u == nil {
			ra, _ := net.ResolveUDPAddr("udp4", f.target)
			if u, e = net.DialUDP("udp4", nil, ra); e != nil {
				continue
			}
			if !f.track(u) {
				return
			}
			peers[src] = u
			f.wg.Add(1)
			go func(u *net.UDPConn, src netip.AddrPort) {
				defer f.wg.Done()
				rb := make([]byte, 65535)
				for {
					n, e := u.Read(rb)
					if e != nil {
						return
					}
					f.pc.WriteToUDPAddrPort(rb[:n], src)
				}
			}(u, src)
		}
		u.Write(b[:n])
	}
}

type fwdSnap map[string][2]int64

func snapshot(fs ...*e2eFwd) fwdSnap {
	m := fwdSnap{}
	for _, f := range fs {
		m[f.name] = [2]int64{f.tcp.Load(), f.udp.Load()}
	}
	return m
}

// delta returns per-forwarder (tcp, udp) increments since s.
func delta(s fwdSnap, fs ...*e2eFwd) map[string][2]int64 {
	m := map[string][2]int64{}
	for _, f := range fs {
		m[f.name] = [2]int64{f.tcp.Load() - s[f.name][0], f.udp.Load() - s[f.name][1]}
	}
	return m
}

// ---- processes ----

type e2eProc struct {
	w       *e2eWorld
	name    string
	port    int
	cfgPath string
	logPath string
	argv    []string
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan error
	logFile *os.File
}

func (w *e2eWorld) process(name string, port int, cfg any, argv func(cfgPath string) []string) *e2eProc {
	b, e := json.MarshalIndent(cfg, "", "  ")
	if e != nil {
		w.t.Fatal(e)
	}
	p := &e2eProc{w: w, name: name, port: port, cfgPath: filepath.Join(w.dir, name+".json"), logPath: filepath.Join(w.dir, name+".log")}
	if e = os.WriteFile(p.cfgPath, b, 0600); e != nil {
		w.t.Fatal(e)
	}
	p.argv = argv(p.cfgPath)
	w.procs = append(w.procs, p)
	p.start()
	return p
}
func (p *e2eProc) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	lf, e := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		p.w.t.Fatal(e)
	}
	cmd := exec.Command(p.argv[0], p.argv[1:]...)
	cmd.Stdout, cmd.Stderr = lf, lf
	if e = cmd.Start(); e != nil {
		lf.Close()
		p.w.t.Fatal(e)
	}
	p.cmd, p.logFile, p.done = cmd, lf, make(chan error, 1)
	go func(c *exec.Cmd, d chan error) { d <- c.Wait() }(cmd, p.done)
	p.w.logf("process %s pid=%d port=%d started: %s", p.name, cmd.Process.Pid, p.port, strings.Join(p.argv, " "))
	for range 200 {
		c, e := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p.port), 50*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	p.w.t.Fatalf("%s did not listen on %d", p.name, p.port)
}

// kill ends the process abruptly (an upstream "being killed").
func (p *e2eProc) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return
	}
	pid := p.cmd.Process.Pid
	p.cmd.Process.Kill()
	<-p.done
	p.logFile.Close()
	p.cmd = nil
	p.w.logf("process %s pid=%d killed (SIGKILL)", p.name, pid)
}

// term sends SIGTERM and returns the exit error (nil = exit status 0).
func (p *e2eProc) term(timeout time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return errors.New("not running")
	}
	pid := p.cmd.Process.Pid
	p.cmd.Process.Signal(syscall.SIGTERM)
	var e error
	select {
	case e = <-p.done:
	case <-time.After(timeout):
		p.cmd.Process.Kill()
		<-p.done
		e = errors.New("did not exit after SIGTERM")
	}
	p.logFile.Close()
	p.cmd = nil
	p.w.logf("process %s pid=%d SIGTERM exit=%v", p.name, pid, e)
	return e
}
func (p *e2eProc) text() string {
	b, _ := os.ReadFile(p.logPath)
	return string(b)
}

// countLines counts log lines matching re (sing-box connection log, events).
func (p *e2eProc) countLines(re *regexp.Regexp) int {
	n := 0
	sc := bufio.NewScanner(strings.NewReader(p.text()))
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		if re.MatchString(sc.Text()) {
			n++
		}
	}
	return n
}

// waitLines waits until countLines(re) >= n.
func (p *e2eProc) waitLines(re *regexp.Regexp, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if p.countLines(re) >= n {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sbConn matches sing-box's info-level log line for one proxied TCP
// connection to the echo port (probe connections go to the HTTP port).
func sbConn(port uint16) *regexp.Regexp {
	return regexp.MustCompile(`inbound connection to [^ ]+:` + strconv.Itoa(int(port)) + `$`)
}

func (w *e2eWorld) singbox(name string, port int, inbound map[string]any) *e2eProc {
	if port == 0 {
		port = e2eFreePort(w.t)
	}
	inbound["tag"], inbound["listen"], inbound["listen_port"] = "in", "127.0.0.1", port
	_, dnsPort, _ := net.SplitHostPort(w.dns.udp.LocalAddr().String())
	dp, _ := strconv.Atoi(dnsPort)
	cfg := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "test-dns", "server": "127.0.0.1", "server_port": dp}}},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"default_domain_resolver": "test-dns"},
	}
	return w.process(name, port, cfg, func(c string) []string { return []string{w.sb, "run", "-c", c} })
}
func (w *e2eWorld) sbSS(name string, port int) *e2eProc {
	return w.singbox(name, port, map[string]any{"type": "shadowsocks", "method": e2eMethod, "password": e2eSBKey})
}
func (w *e2eWorld) sbTrojan(name string) *e2eProc {
	return w.singbox(name, 0, map[string]any{"type": "trojan", "users": []any{map[string]any{"name": "u", "password": e2eTrojanPass}},
		"tls": map[string]any{"enabled": true, "certificate_path": w.cert, "key_path": w.key}})
}
func (w *e2eWorld) sbAnyTLS(name string) *e2eProc {
	return w.singbox(name, 0, map[string]any{"type": "anytls", "users": []any{map[string]any{"name": "kat", "password": e2eAnyTLSPass}},
		"tls": map[string]any{"enabled": true, "certificate_path": w.cert, "key_path": w.key}})
}

// katProc runs the Kat binary under test with cfg (the "listen" of the first
// inbound decides the readiness port).
func (w *e2eWorld) katProc(name string, cfg map[string]any) *e2eProc {
	ins := cfg["inbounds"].([]any)
	_, p, _ := net.SplitHostPort(ins[0].(map[string]any)["listen"].(string))
	port, _ := strconv.Atoi(p)
	return w.process(name, port, cfg, func(c string) []string { return []string{w.kat, "run", c} })
}
func (w *e2eWorld) dnsServer() string { return "udp://" + w.dns.udp.LocalAddr().String() }
func (w *e2eWorld) katUpstream(name string, inbound map[string]any) *e2eProc {
	port := e2eFreePort(w.t)
	inbound["listen"] = "127.0.0.1:" + strconv.Itoa(port)
	return w.katProc(name, map[string]any{"dns": map[string]any{"server": w.dnsServer()}, "udp_bind_ipv4": "127.0.0.1", "inbounds": []any{inbound}})
}

// entry starts the Kat under test with a SOCKS5 and an SS2022 inbound.
func (w *e2eWorld) entry(extra map[string]any) (*e2eProc, *e2eClients) {
	sp, qp := e2eFreePort(w.t), e2eFreePort(w.t)
	cfg := map[string]any{
		"udp_bind_ipv4": "127.0.0.1",
		"inbounds": []any{
			map[string]any{"protocol": "socks5", "listen": "127.0.0.1:" + strconv.Itoa(sp)},
			map[string]any{"protocol": "shadowsocks", "listen": "127.0.0.1:" + strconv.Itoa(qp), "ss": map[string]any{"method": e2eMethod, "key": e2eEntryKey}},
		},
		"limits": map[string]any{"dial_timeout": "3s", "handshake_timeout": "5s", "udp_idle": "10s", "drain_timeout": "3s"},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	p := w.katProc("entry", cfg)
	d := direct.New(direct.Options{})
	sc, e := socks5.New(outbound.Options{Name: "socks-client", Type: "socks5", Server: "127.0.0.1", Port: uint16(sp)}, d)
	if e != nil {
		w.t.Fatal(e)
	}
	qc, e := ss.New(outbound.Options{Name: "ss-client", Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(qp), Method: e2eMethod, Key: e2eEntryKey}, d)
	if e != nil {
		w.t.Fatal(e)
	}
	return p, &e2eClients{socks: sc, ss: qc}
}

type e2eClients struct{ socks, ss outbound.Outbound }

// stopEntry: graceful SIGTERM must exit 0 within the drain budget, log
// "kat event=stopped" and never leak destinations/credentials into stderr.
func (w *e2eWorld) stopEntry(p *e2eProc) {
	w.t.Helper()
	if e := p.term(10 * time.Second); e != nil {
		w.t.Fatalf("entry did not exit cleanly: %v", e)
	}
	out := p.text()
	if !strings.Contains(out, "kat event=stopped") || strings.Contains(out, "drain_deadline") {
		w.t.Fatalf("entry shutdown not clean:\n%s", out)
	}
	for _, secret := range []string{"e2e.test", "127.0.0.2", "127.0.0.3", e2eEntryKey, e2eSBKey, e2eKatKey, e2eTrojanPass, e2eAnyTLSPass} {
		if strings.Contains(out, secret) {
			w.t.Fatalf("entry stderr leaked %q", secret)
		}
	}
	w.logf("entry stderr (full):\n%s", out)
}

// ---- traffic helpers ----

func e2eTCP(d outbound.Dialer, host string, port uint16) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, e := d.DialTCP(ctx, outbound.Addr{Host: host, Port: port})
	if e != nil {
		return fmt.Errorf("dial: %w", e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	p := make([]byte, 20000)
	rand.Read(p)
	go c.Write(p)
	got := make([]byte, len(p))
	if _, e = io.ReadFull(c, got); e != nil {
		return fmt.Errorf("read: %w", e)
	}
	if !bytes.Equal(got, p) {
		return errors.New("echo mismatch")
	}
	return nil
}

func e2eUDP(d outbound.Dialer, host string, port uint16, tries int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, e := d.ListenPacket(ctx)
	if e != nil {
		return fmt.Errorf("listen: %w", e)
	}
	defer pc.Close()
	b := make([]byte, 65535)
	for _, size := range []int{1, 1200} {
		p := make([]byte, size)
		rand.Read(p)
		ok := false
		for i := 0; i < tries && !ok; i++ {
			if _, e := pc.WriteTo(p, outbound.Addr{Host: host, Port: port}); e != nil {
				return fmt.Errorf("write: %w", e)
			}
			pc.SetReadDeadline(time.Now().Add(time.Second))
			for {
				n, _, e := pc.ReadFrom(b)
				if e != nil {
					break
				}
				if bytes.Equal(b[:n], p) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return fmt.Errorf("no echo for %d-byte datagram", size)
		}
	}
	return nil
}

func (w *e2eWorld) must(what string, e error) {
	w.t.Helper()
	if e != nil {
		w.t.Fatalf("%s: %v", what, e)
	}
	w.logf("OK %s", what)
}

func (w *e2eWorld) expect(what string, got map[string][2]int64, want map[string][2]int64) {
	w.t.Helper()
	for k, v := range want {
		g := got[k]
		// -1 means "at least one".
		if v[0] == -1 && g[0] < 1 || v[0] >= 0 && g[0] != v[0] || v[1] == -1 && g[1] < 1 || v[1] >= 0 && g[1] != v[1] {
			w.t.Fatalf("%s: forwarder %s delta (tcp,udp)=%v want %v (all: %v)", what, k, g, v, got)
		}
	}
	w.logf("EVIDENCE %s: forwarder deltas (tcp_conns,udp_datagrams)=%v", what, got)
}

// ---- 1. default configuration: inbounds only ----

func TestE2EDefaultDirect(t *testing.T) {
	w := e2eSetup(t)
	p, c := w.entry(nil)
	for _, cl := range []struct {
		n string
		d outbound.Dialer
	}{{"socks5", c.socks}, {"ss2022", c.ss}} {
		w.must(cl.n+" TCP direct echo (IP literal)", e2eTCP(cl.d, "127.0.0.1", w.echoTCP["127.0.0.1"]))
		w.must(cl.n+" TCP direct echo (system resolver: localhost)", e2eTCP(cl.d, "localhost", w.echoTCP["127.0.0.1"]))
		w.must(cl.n+" UDP direct echo", e2eUDP(cl.d, "127.0.0.1", w.echoUDP, 3))
	}
	if n := w.dns.count.Load(); n != 0 {
		t.Fatalf("default configuration queried the test DNS server %d times", n)
	}
	w.stopEntry(p)
}

// ---- 2. rules ----

func (w *e2eWorld) writeFile(name, body string) string {
	p := filepath.Join(w.dir, name)
	if e := os.WriteFile(p, []byte(body), 0600); e != nil {
		w.t.Fatal(e)
	}
	return p
}

func TestE2ERules(t *testing.T) {
	w := e2eSetup(t)
	sbss, sbtr, sbany := w.sbSS("sb-ss", 0), w.sbTrojan("sb-trojan"), w.sbAnyTLS("sb-anytls")
	ks := w.katUpstream("kat-socks", map[string]any{"protocol": "socks5"})
	fSS, fTr, fAny, fKs := w.forwarder("ss_sb", sbss.port, 0), w.forwarder("trojan_sb", sbtr.port, 0), w.forwarder("anytls_sb", sbany.port, 0), w.forwarder("socks_kat", ks.port, 0)
	all := []*e2eFwd{fSS, fTr, fAny, fKs}
	blocked := w.writeFile("blocked.txt", "# test domain rule set\n.blocked.e2e.test\n")
	ips := w.writeFile("ips.txt", "# test ipcidr rule set\n127.0.0.2/32\n")
	mmdb := filepath.Join(w.dir, "country.mmdb")
	os.WriteFile(mmdb, e2eMMDB(map[string]string{"127.0.0.3/32": "JP"}), 0600)
	tlsPin := map[string]any{"pin_sha256": w.pin}
	p, c := w.entry(map[string]any{
		"dns": map[string]any{"server": w.dnsServer()},
		"outbounds": []any{
			map[string]any{"name": "ss_sb", "type": "shadowsocks", "server": "127.0.0.1", "port": fSS.port, "method": e2eMethod, "key": e2eSBKey},
			map[string]any{"name": "trojan_sb", "type": "trojan", "server": "127.0.0.1", "port": fTr.port, "password": e2eTrojanPass, "tls": tlsPin},
			map[string]any{"name": "anytls_sb", "type": "anytls", "server": "127.0.0.1", "port": fAny.port, "password": e2eAnyTLSPass, "tls": tlsPin},
			map[string]any{"name": "socks_kat", "type": "socks5", "server": "127.0.0.1", "port": fKs.port},
		},
		"groups":    []any{map[string]any{"name": "sel", "type": "select", "members": []any{"ss_sb", "trojan_sb"}, "selected": "trojan_sb"}},
		"rule_sets": []any{map[string]any{"name": "blocked", "format": "domain", "path": blocked}, map[string]any{"name": "ips", "format": "ipcidr", "path": ips}},
		"geoip":     map[string]any{"path": mmdb},
		"routing": map[string]any{"rules": []any{
			map[string]any{"rule_set": "blocked", "action": "reject"},
			map[string]any{"domain_suffix": "via-ss.e2e.test", "outbound": "ss_sb"},
			map[string]any{"network": "udp", "outbound": "anytls_sb"},
			map[string]any{"rule_set": "ips", "outbound": "sel"},
			map[string]any{"geoip": "JP", "action": "direct"},
		}, "final": "socks_kat"},
	})
	if !p.waitLines(regexp.MustCompile(`kat event=rule_set_loaded name=blocked entries=1 skipped=0`), 1, 2*time.Second) ||
		!p.waitLines(regexp.MustCompile(`kat event=rule_set_loaded name=ips entries=1 skipped=0`), 1, 2*time.Second) ||
		!p.waitLines(regexp.MustCompile(`kat event=geoip_loaded`), 1, 2*time.Second) {
		t.Fatalf("rule data load events missing:\n%s", p.text())
	}
	w.logf("EVIDENCE rule_set_loaded/geoip_loaded events present in entry.log")
	e1 := w.echoTCP["127.0.0.1"]
	for _, cl := range []struct {
		n string
		d outbound.Dialer
	}{{"socks5", c.socks}, {"ss2022", c.ss}} {
		// domain_suffix -> ss_sb
		s := snapshot(all...)
		w.must(cl.n+" TCP x.via-ss.e2e.test (domain_suffix -> ss_sb)", e2eTCP(cl.d, "x.via-ss.e2e.test", e1))
		w.expect(cl.n+" domain_suffix->ss_sb", delta(s, all...), map[string][2]int64{"ss_sb": {1, 0}, "trojan_sb": {0, 0}, "anytls_sb": {0, 0}, "socks_kat": {0, 0}})
		// rule_set(domain) -> reject, decided before DNS
		s, q := snapshot(all...), w.dns.count.Load()
		if e := e2eTCP(cl.d, "ads.blocked.e2e.test", e1); e == nil {
			t.Fatal("rule_set reject dialed")
		}
		if w.dns.count.Load() != q {
			t.Fatal("pre-DNS rule_set reject queried DNS")
		}
		w.expect(cl.n+" rule_set(domain)->reject (no DNS query)", delta(s, all...), map[string][2]int64{"ss_sb": {0, 0}, "trojan_sb": {0, 0}, "anytls_sb": {0, 0}, "socks_kat": {0, 0}})
		// rule_set(ipcidr) -> select group (selected trojan_sb)
		s = snapshot(all...)
		w.must(cl.n+" TCP 127.0.0.2 (rule_set ipcidr -> group sel -> trojan_sb)", e2eTCP(cl.d, "127.0.0.2", w.echoTCP["127.0.0.2"]))
		w.expect(cl.n+" rule_set(ipcidr)->sel(select: trojan_sb)", delta(s, all...), map[string][2]int64{"ss_sb": {0, 0}, "trojan_sb": {1, 0}, "anytls_sb": {0, 0}, "socks_kat": {0, 0}})
		// geoip (test mmdb: 127.0.0.3 = JP) -> direct
		s = snapshot(all...)
		w.must(cl.n+" TCP 127.0.0.3 (geoip JP -> direct)", e2eTCP(cl.d, "127.0.0.3", w.echoTCP["127.0.0.3"]))
		w.expect(cl.n+" geoip->direct", delta(s, all...), map[string][2]int64{"ss_sb": {0, 0}, "trojan_sb": {0, 0}, "anytls_sb": {0, 0}, "socks_kat": {0, 0}})
		// final -> socks_kat (domain resolved locally only for IP rules; upstream Kat resolves again)
		s = snapshot(all...)
		w.must(cl.n+" TCP final.e2e.test (final -> socks_kat)", e2eTCP(cl.d, "final.e2e.test", e1))
		w.expect(cl.n+" final->socks_kat", delta(s, all...), map[string][2]int64{"ss_sb": {0, 0}, "trojan_sb": {0, 0}, "anytls_sb": {0, 0}, "socks_kat": {1, 0}})
		// network udp -> anytls_sb (UoT over the TCP/TLS session)
		s = snapshot(all...)
		w.must(cl.n+" UDP 127.0.0.1 (network udp -> anytls_sb UoT)", e2eUDP(cl.d, "127.0.0.1", w.echoUDP, 3))
		d := delta(s, all...)
		if d["ss_sb"] != [2]int64{} || d["trojan_sb"] != [2]int64{} || d["socks_kat"] != [2]int64{} || fAny.tcp.Load() < 1 || sbany.countLines(regexp.MustCompile(`inbound UoT connection`)) < 1 {
			t.Fatalf("network udp did not go through anytls_sb: %v any_tcp_total=%d\n%s", d, fAny.tcp.Load(), sbany.text())
		}
		w.logf("EVIDENCE %s network udp->anytls_sb: deltas %v, anytls forwarder tcp total=%d, sing-box anytls UoT connection lines=%d", cl.n, d, fAny.tcp.Load(), sbany.countLines(regexp.MustCompile(`inbound UoT connection`)))
		// domain_suffix before the network rule: UDP -> ss_sb native UDP
		s = snapshot(all...)
		w.must(cl.n+" UDP u.via-ss.e2e.test (domain_suffix -> ss_sb native UDP)", e2eUDP(cl.d, "u.via-ss.e2e.test", w.echoUDP, 3))
		w.expect(cl.n+" udp domain_suffix->ss_sb native", delta(s, all...), map[string][2]int64{"ss_sb": {0, -1}, "trojan_sb": {0, 0}, "socks_kat": {0, 0}})
	}
	w.stopEntry(p)
}

// ---- 3. chains ----

func TestE2EChains(t *testing.T) {
	w := e2eSetup(t)
	sbss, sbtr, sbany := w.sbSS("sb-ss", 0), w.sbTrojan("sb-trojan"), w.sbAnyTLS("sb-anytls")
	kss := w.katUpstream("kat-ss", map[string]any{"protocol": "shadowsocks", "ss": map[string]any{"method": e2eMethod, "key": e2eKatKey}})
	ks := w.katUpstream("kat-socks", map[string]any{"protocol": "socks5"})
	fSS, fTr, fAny, fKss, fKs := w.forwarder("ss_sb", sbss.port, 0), w.forwarder("trojan_sb", sbtr.port, 0), w.forwarder("anytls_sb", sbany.port, 0), w.forwarder("kat_ss", kss.port, 0), w.forwarder("socks_kat", ks.port, 0)
	all := []*e2eFwd{fSS, fTr, fAny, fKss, fKs}
	pin := map[string]any{"pin_sha256": w.pin}
	p, c := w.entry(map[string]any{
		"dns": map[string]any{"server": w.dnsServer()},
		"outbounds": []any{
			map[string]any{"name": "ss_sb", "type": "shadowsocks", "server": "127.0.0.1", "port": fSS.port, "method": e2eMethod, "key": e2eSBKey},
			map[string]any{"name": "trojan_via_ss", "type": "trojan", "server": "127.0.0.1", "port": fTr.port, "password": e2eTrojanPass, "tls": pin, "via": "ss_sb"},
			map[string]any{"name": "anytls_sb", "type": "anytls", "server": "127.0.0.1", "port": fAny.port, "password": e2eAnyTLSPass, "tls": pin},
			map[string]any{"name": "ss_kat_via_anytls", "type": "shadowsocks", "server": "127.0.0.1", "port": fKss.port, "method": e2eMethod, "key": e2eKatKey, "via": "anytls_sb"},
			map[string]any{"name": "socks_tcp_only", "type": "socks5", "server": "127.0.0.1", "port": fKs.port, "udp": false},
			map[string]any{"name": "ss_kat_via_tcp_only", "type": "shadowsocks", "server": "127.0.0.1", "port": fKss.port, "method": e2eMethod, "key": e2eKatKey, "via": "socks_tcp_only"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"domain_suffix": "chain-tcp.e2e.test", "outbound": "trojan_via_ss"},
			map[string]any{"domain_suffix": "chain-udp.e2e.test", "outbound": "ss_kat_via_anytls"},
			map[string]any{"domain_suffix": "chain-drop.e2e.test", "outbound": "ss_kat_via_tcp_only"},
		}},
	})
	e1 := w.echoTCP["127.0.0.1"]
	// (a) TCP: trojan via ss (two proxy hops)
	s := snapshot(all...)
	w.must("socks5 TCP a.chain-tcp.e2e.test (trojan via ss)", e2eTCP(c.socks, "a.chain-tcp.e2e.test", e1))
	w.expect("TCP two-hop trojan via ss", delta(s, all...), map[string][2]int64{"ss_sb": {1, 0}, "trojan_sb": {1, 0}, "anytls_sb": {0, 0}, "kat_ss": {0, 0}})
	s = snapshot(all...)
	w.must("ss2022 TCP b.chain-tcp.e2e.test (trojan via ss)", e2eTCP(c.ss, "b.chain-tcp.e2e.test", e1))
	w.expect("TCP two-hop trojan via ss (SS2022 inbound)", delta(s, all...), map[string][2]int64{"ss_sb": {1, 0}, "trojan_sb": {1, 0}})
	// (b) UDP: SS2022 native UDP carried by AnyTLS UoT
	for _, cl := range []struct {
		n string
		d outbound.Dialer
	}{{"socks5", c.socks}, {"ss2022", c.ss}} {
		s = snapshot(all...)
		w.must(cl.n+" UDP u.chain-udp.e2e.test (ss native UDP via anytls UoT)", e2eUDP(cl.d, "u.chain-udp.e2e.test", w.echoUDP, 3))
		d := delta(s, all...)
		if d["kat_ss"][1] < 1 || d["ss_sb"] != [2]int64{} || fAny.tcp.Load() < 1 {
			t.Fatalf("UDP two-hop evidence missing: %v", d)
		}
		w.logf("EVIDENCE %s UDP two-hop: deltas %v (kat_ss udp datagrams arrive from the anytls server; anytls forwarder tcp total=%d)", cl.n, d, fAny.tcp.Load())
	}
	// (c) SS native UDP over a TCP-only hop: dropped and reported; TCP still works.
	s = snapshot(all...)
	if e := e2eUDP(c.socks, "u.chain-drop.e2e.test", w.echoUDP, 2); e == nil {
		t.Fatal("UDP over a TCP-only hop echoed")
	}
	w.expect("UDP over TCP-only hop dropped (no datagram reaches kat_ss)", delta(s, all...), map[string][2]int64{"kat_ss": {0, 0}, "socks_kat": {0, 0}})
	if !p.waitLines(regexp.MustCompile(`kat event=failure stage=outbound reason=udp_unsupported`), 1, 2*time.Second) {
		t.Fatalf("udp_unsupported failure category missing:\n%s", p.text())
	}
	w.logf("EVIDENCE entry.log: kat event=failure stage=outbound reason=udp_unsupported")
	s = snapshot(all...)
	w.must("socks5 TCP t.chain-drop.e2e.test (ss via TCP-only socks5)", e2eTCP(c.socks, "t.chain-drop.e2e.test", e1))
	w.expect("TCP over TCP-only hop", delta(s, all...), map[string][2]int64{"socks_kat": {1, 0}, "kat_ss": {1, 0}})
	w.stopEntry(p)
}

// ---- 4. groups: select + url-test ----

func TestE2EGroupsSelectURLTest(t *testing.T) {
	w := e2eSetup(t)
	sbss := w.sbSS("sb-ss", 0)
	fSlow, fFast := w.forwarder("slow", sbss.port, 400*time.Millisecond), w.forwarder("fast", sbss.port, 0)
	all := []*e2eFwd{fSlow, fFast}
	ob := func(name string, port int) map[string]any {
		return map[string]any{"name": name, "type": "shadowsocks", "server": "127.0.0.1", "port": port, "method": e2eMethod, "key": e2eSBKey}
	}
	probe := "http://127.0.0.1:" + strconv.Itoa(w.httpPort) + "/generate_204"
	p, c := w.entry(map[string]any{
		"dns":       map[string]any{"server": w.dnsServer()},
		"outbounds": []any{ob("slow", fSlow.port), ob("fast", fFast.port)},
		"groups": []any{
			map[string]any{"name": "sel", "type": "select", "members": []any{"slow", "fast"}, "selected": "fast"},
			map[string]any{"name": "ut", "type": "url-test", "members": []any{"slow", "fast"}, "probe": map[string]any{"url": probe, "interval": "10m", "timeout": "3s"}},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"domain_suffix": "sel.e2e.test", "outbound": "sel"}}, "final": "ut"},
	})
	e1 := w.echoTCP["127.0.0.1"]
	s := snapshot(all...)
	w.must("select group (selected=fast)", e2eTCP(c.socks, "a.sel.e2e.test", e1))
	w.expect("select uses configured selected member", delta(s, all...), map[string][2]int64{"fast": {1, 0}, "slow": {0, 0}})
	// url-test: first use goes to the first member and triggers the probe round.
	w.must("url-test first connection", e2eTCP(c.socks, "b.ut.e2e.test", e1))
	switchRE := regexp.MustCompile(`kat event=group_switch group=ut from=slow to=fast`)
	if !p.waitLines(switchRE, 1, 15*time.Second) {
		t.Fatalf("url-test did not switch to the faster member:\n%s", p.text())
	}
	w.logf("EVIDENCE entry.log: %s (probe requests served=%d)", switchRE, w.httpCount.Load())
	s = snapshot(all...)
	for i := range 3 {
		w.must(fmt.Sprintf("url-test connection %d after probe", i), e2eTCP(c.socks, "c.ut.e2e.test", e1))
	}
	w.expect("url-test uses faster member (slow forwarder adds 400ms)", delta(s, all...), map[string][2]int64{"fast": {3, 0}, "slow": {0, 0}})
	w.stopEntry(p)
}

// ---- 4/5. fallback: failover, transparent in-group retry, recovery ----

func TestE2EFallbackFailover(t *testing.T) {
	w := e2eSetup(t)
	portA, portB := e2eFreePort(t), e2eFreePort(t)
	pa, pb := w.sbSS("sb-ss-A", portA), w.sbSS("sb-ss-B", portB)
	ob := func(name string, port int) map[string]any {
		return map[string]any{"name": name, "type": "shadowsocks", "server": "127.0.0.1", "port": port, "method": e2eMethod, "key": e2eSBKey}
	}
	probe := "http://127.0.0.1:" + strconv.Itoa(w.httpPort) + "/"
	p, c := w.entry(map[string]any{
		"dns":       map[string]any{"server": w.dnsServer()},
		"outbounds": []any{ob("fb1", portA), ob("fb2", portB), ob("r1", portA), ob("r2", portB)},
		"groups": []any{
			map[string]any{"name": "fb", "type": "fallback", "members": []any{"fb1", "fb2"}, "probe": map[string]any{"url": probe, "interval": "1s", "timeout": "1s"}},
			// Long interval: no probe can notice the failure before the retry test.
			map[string]any{"name": "fbr", "type": "fallback", "members": []any{"r1", "r2"}, "probe": map[string]any{"url": probe, "interval": "10m", "timeout": "1s"}},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"domain_suffix": "retry.e2e.test", "outbound": "fbr"}}, "final": "fb"},
	})
	e1 := w.echoTCP["127.0.0.1"]
	sbConnRE := sbConn(e1)
	nA, nB := pa.countLines(sbConnRE), pb.countLines(sbConnRE)
	w.must("fallback first connection", e2eTCP(c.socks, "a.fb.e2e.test", e1))
	w.must("fallback retry-group first connection", e2eTCP(c.socks, "a.retry.e2e.test", e1))
	if !pa.waitLines(sbConnRE, nA+2, 3*time.Second) || pb.countLines(sbConnRE) != nB {
		t.Fatalf("fallback did not start on the first member (A %d->%d, B %d->%d)", nA, pa.countLines(sbConnRE), nB, pb.countLines(sbConnRE))
	}
	w.logf("EVIDENCE fallback initial: sing-box A connection log lines %d->%d, B unchanged %d", nA, pa.countLines(sbConnRE), nB)
	// An established connection through A.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	live, e := c.socks.DialTCP(ctx, outbound.Addr{Host: "live.fb.e2e.test", Port: e1})
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	live.Write([]byte("ping"))
	buf := make([]byte, 4)
	live.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, e = io.ReadFull(live, buf); e != nil {
		t.Fatal("live connection echo:", e)
	}
	// Kill upstream A.
	pa.kill()
	start := time.Now()
	live.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, e = live.Read(buf)
	if e == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("established connection did not fail promptly after upstream death: %v after %s", e, time.Since(start))
	}
	w.logf("EVIDENCE established connection through killed upstream ended with %q after %s (no hang)", e, time.Since(start).Round(time.Millisecond))
	// Transparent in-group retry: fbr still prefers r1 (no probe for 10m); r1's
	// dial fails (A is dead) and the same client connection is served by r2.
	if strings.Contains(p.text(), "group=fbr") {
		t.Fatal("fbr switched before the retry check")
	}
	nB = pb.countLines(sbConnRE)
	w.must("fallback retry-group connection while A is dead (r1 dial fails -> r2)", e2eTCP(c.socks, "b.retry.e2e.test", e1))
	if !pb.waitLines(sbConnRE, nB+1, 3*time.Second) {
		t.Fatal("retry did not reach B")
	}
	w.logf("EVIDENCE in-group retry: client connection succeeded; sing-box B lines %d->%d; fbr had no prior switch event", nB, pb.countLines(sbConnRE))
	// Main fallback group: switches to fb2 and new connections succeed.
	toB := regexp.MustCompile(`kat event=group_switch group=fb from=fb1 to=fb2`)
	deadline := time.Now().Add(15 * time.Second)
	for p.countLines(toB) < 1 && time.Now().Before(deadline) {
		e2eTCP(c.socks, "poll.fb.e2e.test", e1)
		time.Sleep(300 * time.Millisecond)
	}
	if p.countLines(toB) < 1 {
		t.Fatalf("fallback did not switch to fb2:\n%s", p.text())
	}
	nB = pb.countLines(sbConnRE)
	w.must("fallback connection after failover", e2eTCP(c.socks, "c.fb.e2e.test", e1))
	if !pb.waitLines(sbConnRE, nB+1, 3*time.Second) {
		t.Fatal("failover connection did not reach B")
	}
	w.logf("EVIDENCE entry.log: %s; B lines %d->%d", toB, nB, pb.countLines(sbConnRE))
	// Recover A on the same port: the probe (1s) brings fb back to fb1.
	pa.start()
	toA := regexp.MustCompile(`kat event=group_switch group=fb from=fb2 to=fb1`)
	deadline = time.Now().Add(20 * time.Second)
	for p.countLines(toA) < 1 && time.Now().Before(deadline) {
		e2eTCP(c.socks, "poll.fb.e2e.test", e1) // keeps the lazy group in use
		time.Sleep(300 * time.Millisecond)
	}
	if p.countLines(toA) < 1 {
		t.Fatalf("fallback did not switch back to fb1:\n%s", p.text())
	}
	nA = pa.countLines(sbConnRE)
	w.must("fallback connection after recovery", e2eTCP(c.socks, "d.fb.e2e.test", e1))
	if !pa.waitLines(sbConnRE, nA+1, 3*time.Second) {
		t.Fatal("recovered connection did not reach A")
	}
	w.logf("EVIDENCE entry.log: %s; A (restarted) lines %d->%d", toA, nA, pa.countLines(sbConnRE))
	live.Close()
	w.stopEntry(p)
}

// ---- 4/5. smart: transfer after the current member's upstream dies ----

func TestE2ESmartFailover(t *testing.T) {
	w := e2eSetup(t)
	procs := map[string]*e2eProc{"sm1": w.sbSS("sb-ss-1", 0), "sm2": w.sbSS("sb-ss-2", 0)}
	ob := func(name string) map[string]any {
		return map[string]any{"name": name, "type": "shadowsocks", "server": "127.0.0.1", "port": procs[name].port, "method": e2eMethod, "key": e2eSBKey}
	}
	probe := "http://127.0.0.1:" + strconv.Itoa(w.httpPort) + "/"
	p, c := w.entry(map[string]any{
		"dns":       map[string]any{"server": w.dnsServer()},
		"outbounds": []any{ob("sm1"), ob("sm2")},
		"groups":    []any{map[string]any{"name": "sm", "type": "smart", "members": []any{"sm1", "sm2"}, "probe": map[string]any{"url": probe, "timeout": "2s"}}},
		"routing":   map[string]any{"final": "sm"},
	})
	e1 := w.echoTCP["127.0.0.1"]
	sbConnRE := sbConn(e1)
	time.Sleep(time.Second) // let the start-up probe round finish
	n1, n2 := procs["sm1"].countLines(sbConnRE), procs["sm2"].countLines(sbConnRE)
	w.must("smart first connection", e2eTCP(c.socks, "a.sm.e2e.test", e1))
	time.Sleep(300 * time.Millisecond)
	cur, other := "sm1", "sm2"
	if procs["sm2"].countLines(sbConnRE) > n2 && procs["sm1"].countLines(sbConnRE) == n1 {
		cur, other = "sm2", "sm1"
	}
	w.logf("EVIDENCE smart current member before failure: %s (sing-box connection log lines sm1 %d->%d, sm2 %d->%d)", cur, n1, procs["sm1"].countLines(sbConnRE), n2, procs["sm2"].countLines(sbConnRE))
	procs[cur].kill()
	nO := procs[other].countLines(sbConnRE)
	w.must("smart connection right after the current member's upstream died", e2eTCP(c.socks, "b.sm.e2e.test", e1))
	sw := regexp.MustCompile(`kat event=group_switch group=sm from=` + cur + ` to=` + other)
	if !p.waitLines(sw, 1, 5*time.Second) {
		t.Fatalf("smart did not emit a switch:\n%s", p.text())
	}
	for i := range 3 {
		w.must(fmt.Sprintf("smart subsequent connection %d", i), e2eTCP(c.socks, "c.sm.e2e.test", e1))
	}
	if !procs[other].waitLines(sbConnRE, nO+4, 3*time.Second) {
		t.Fatalf("smart connections did not reach %s", other)
	}
	w.logf("EVIDENCE entry.log: %s; %s connection lines %d->%d", sw, other, nO, procs[other].countLines(sbConnRE))
	w.stopEntry(p)
}

// ---- test GeoIP database (MaxMind DB v2 writer, Kat's own route test helper) ----

func e2eMMDB(nets map[string]string) []byte {
	type node struct {
		child [2]*node
		data  int
	}
	var codes []string
	root := &node{data: -1}
	for cidr, code := range nets {
		codes = append(codes, code)
		p := netip.MustParsePrefix(cidr)
		ip16, bits := p.Addr().As16(), p.Bits()
		if p.Addr().Is4() {
			ip16 = [16]byte{}
			a4 := p.Addr().As4()
			copy(ip16[12:], a4[:])
			bits += 96
		}
		n := root
		for i := 0; i < bits; i++ {
			b := ip16[i/8] >> (7 - i%8) & 1
			if n.child[b] == nil {
				n.child[b] = &node{data: -1}
			}
			n = n.child[b]
		}
		n.data = len(codes) - 1
	}
	ctrl := func(typ, size int) []byte {
		first := byte(typ << 5)
		var ext []byte
		if typ > 7 {
			first, ext = 0, []byte{byte(typ - 7)}
		}
		if size >= 29 {
			panic("e2eMMDB: field too large")
		}
		return append([]byte{first | byte(size)}, ext...)
	}
	str := func(s string) []byte { return append(ctrl(2, len(s)), s...) }
	uintv := func(typ int, v uint64) []byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		i := 0
		for i < 8 && b[i] == 0 {
			i++
		}
		return append(ctrl(typ, 8-i), b[i:]...)
	}
	var order []*node
	id := map[*node]int{}
	queue := []*node{root}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		id[n] = len(order)
		order = append(order, n)
		for _, c := range n.child {
			if c != nil && c.data < 0 {
				queue = append(queue, c)
			}
		}
	}
	var data []byte
	offsets := make([]int, len(codes))
	for i, c := range codes {
		offsets[i] = len(data)
		// {"country": {"iso_code": c}}
		data = append(data, ctrl(7, 1)...)
		data = append(data, str("country")...)
		data = append(data, ctrl(7, 1)...)
		data = append(data, str("iso_code")...)
		data = append(data, str(c)...)
	}
	nodeCount := len(order)
	var out bytes.Buffer
	for _, n := range order {
		for _, c := range n.child {
			v := nodeCount
			if c != nil && c.data >= 0 {
				v = nodeCount + 16 + offsets[c.data]
			} else if c != nil {
				v = id[c]
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data)
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	meta := [][2]any{{"binary_format_major_version", uintv(5, 2)}, {"binary_format_minor_version", uintv(5, 0)}, {"build_epoch", uintv(9, 1761264000)},
		{"database_type", str("Kat-E2E-Country")}, {"ip_version", uintv(5, 6)}, {"node_count", uintv(6, uint64(nodeCount))}, {"record_size", uintv(5, 24)}}
	out.Write(ctrl(7, len(meta)))
	for _, kv := range meta {
		out.Write(str(kv[0].(string)))
		out.Write(kv[1].([]byte))
	}
	return out.Bytes()
}
