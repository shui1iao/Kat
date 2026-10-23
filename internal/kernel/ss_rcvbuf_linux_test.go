//go:build linux

package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Real-socket tests for the explicit SS2017 UDP receive buffer and its process budget.

func rcvbufOf(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	raw, e := c.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var v int
	var ge error
	if e = raw.Control(func(fd uintptr) { v, ge = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) }); e != nil || ge != nil {
		t.Fatal(e, ge)
	}
	return v
}
func defaultRcvBuf(t *testing.T) int {
	t.Helper()
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	return rcvbufOf(t, u)
}
func rmemMax(t *testing.T) int {
	b, e := os.ReadFile("/proc/sys/net/core/rmem_max")
	if e != nil {
		t.Fatal(e)
	}
	v, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func rcvbufInbound(password string, enabled bool) Inbound {
	in := Inbound{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: &SSOptions{Method: "aes-128-gcm", Password: password, Salts2017: 64}}
	if enabled {
		in.SS.UDPRcvBuf2017 = ss2017RcvBufActual
	}
	return in
}
func rcvbufConfig(ins ...Inbound) Config {
	return Config{UDPBindIPv4: "127.0.0.1", UDPBindIPv6: "::1", Inbounds: ins, Limits: Limits{Connections: 32, Handshakes: 16, Dials: 8, UDPAssociations: 8, UDPQueue: 4, UDPTargets: 4, PoolBuffers: 4, HandshakeTimeout: Duration(time.Second), DialTimeout: Duration(time.Second), DrainTimeout: Duration(2 * time.Second), UDPIdle: Duration(time.Second)}}
}
func closeNow(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.Close(ctx)
}
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func requirePortFree(t *testing.T, port int) {
	t.Helper()
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if e != nil {
		t.Fatal("UDP listener not closed after failure:", e)
	}
	u.Close()
	l, e := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if e != nil {
		t.Fatal("TCP listener not closed after failure:", e)
	}
	l.Close()
}
func requireUsed(t *testing.T, want int64) {
	t.Helper()
	if got := ssRcvBufUsed.Load(); got != want {
		t.Fatalf("process rcvbuf budget used=%d want=%d", got, want)
	}
}
func requireRcvBufError(t *testing.T, e error, part string) {
	t.Helper()
	var rb *ssRcvBufError
	if e == nil || !errors.As(e, &rb) || !strings.Contains(e.Error(), part) {
		t.Fatalf("want udp_rcvbuf_2017 error containing %q, got %v", part, e)
	}
}

// Expected per-listener charge on this host: actual 1MiB minus the fresh default.
func expectedCharge(t *testing.T) int64 {
	t.Helper()
	if rmemMax(t) < ss2017RcvBufActual/2 {
		t.Skip("host rmem_max cannot grant actual 1MiB; truncation failure covered by TestSS2017RcvBufTruncationAndErrors")
	}
	d := defaultRcvBuf(t)
	if d >= ss2017RcvBufActual {
		t.Skip("host default already >= 1MiB; no-shrink covered by TestSS2017RcvBufNoShrink")
	}
	return int64(ss2017RcvBufActual - d)
}

func TestSS2017RcvBufUnsetKeepsDefault(t *testing.T) {
	base := ssRcvBufUsed.Load()
	def := defaultRcvBuf(t)
	ss22 := ssIn()
	ss22.Listen = "127.0.0.1:0"
	s := startTest(t, rcvbufInbound("rcvbuf-unset", false), func(c *Config) { c.Inbounds = append(c.Inbounds, ss22) })
	if len(s.ssListeners) != 2 {
		t.Fatal("expected SS2017 and SS2022 UDP listeners")
	}
	for _, l := range s.ssListeners {
		if got := rcvbufOf(t, l.socket); got != def || l.rcvbufCharge.Load() != 0 || l.rcvbufActual != 0 {
			t.Fatalf("unset listener changed: rcvbuf=%d default=%d charge=%d", got, def, l.rcvbufCharge.Load())
		}
	}
	if len(s.SSUDPReceiveBuffers()) != 0 {
		t.Fatal("unset listener reported as enabled")
	}
	requireUsed(t, base)
	closeNow(t, s)
	requireUsed(t, base)
}

func TestSS2017RcvBufActualReadBack(t *testing.T) {
	charge := expectedCharge(t)
	base := ssRcvBufUsed.Load()
	def := defaultRcvBuf(t)
	s := startTest(t, rcvbufInbound("rcvbuf-actual", true), nil)
	l := s.ssListeners[0]
	if got := rcvbufOf(t, l.socket); got != ss2017RcvBufActual || l.rcvbufActual != got || l.rcvbufBefore != def {
		t.Fatalf("read-back actual=%d recorded=%d before=%d default=%d", got, l.rcvbufActual, l.rcvbufBefore, def)
	}
	if l.rcvbufCharge.Load() != charge {
		t.Fatalf("charge %d want actual-before %d", l.rcvbufCharge.Load(), charge)
	}
	requireUsed(t, base+charge)
	r := s.SSUDPReceiveBuffers()
	if len(r) != 1 || r[0].Actual != ss2017RcvBufActual || r[0].Default != def || r[0].Charged != charge || r[0].Address != l.socket.LocalAddr().String() {
		t.Fatalf("report %+v", r)
	}
	closeNow(t, s)
	requireUsed(t, base)
	closeNow(t, s) // second Close must not release twice
	requireUsed(t, base)
}

func TestSS2017RcvBufNoShrink(t *testing.T) {
	if rmemMax(t) < ss2017RcvBufActual {
		t.Skip("rmem_max too small to pre-raise a socket above 1MiB without sysctl")
	}
	base := ssRcvBufUsed.Load()
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	raw, _ := u.SyscallConn()
	var se error
	raw.Control(func(fd uintptr) {
		se = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, ss2017RcvBufActual)
	})
	if se != nil {
		t.Fatal(se)
	}
	pre := rcvbufOf(t, u)
	if pre <= ss2017RcvBufActual {
		t.Fatalf("pre-raise failed: %d", pre)
	}
	before, actual, charge, e := setSS2017RcvBuf(u, ss2017RcvBufActual)
	if e != nil || before != pre || actual != pre || charge != 0 || rcvbufOf(t, u) != pre {
		t.Fatalf("existing larger buffer changed: before=%d actual=%d charge=%d now=%d err=%v", before, actual, charge, rcvbufOf(t, u), e)
	}
	requireUsed(t, base)
}

func TestSS2017RcvBufTruncationAndErrors(t *testing.T) {
	base := ssRcvBufUsed.Load()
	for name, c := range map[string]struct {
		reads   []int
		getErr  int // index of failing get, -1 none
		setErr  bool
		wantErr string
		charged int64
	}{
		"truncated":     {[]int{212992, 524288}, -1, false, "below required", 0},
		"set failure":   {[]int{212992}, -1, true, "cannot set", 0},
		"readback fail": {[]int{212992, 0}, 1, false, "cannot read back", 0},
		"initial fail":  {[]int{0}, 0, false, "cannot read SO_RCVBUF", 0},
		"already large": {[]int{2097152}, -1, false, "", 0},
		"exact":         {[]int{212992, 1048576}, -1, false, "", 835584},
	} {
		i, discarded, sets := 0, 0, 0
		var usedAtDiscard int64 = -1
		get := func() (int, error) {
			v := c.reads[i]
			i++
			if i-1 == c.getErr {
				return 0, errors.New("injected")
			}
			return v, nil
		}
		set := func(int) error {
			sets++
			if c.setErr {
				return errors.New("injected")
			}
			return nil
		}
		_, _, charge, e := applySS2017RcvBuf(ss2017RcvBufActual, get, set, func() { discarded++; usedAtDiscard = ssRcvBufUsed.Load() })
		if c.wantErr != "" {
			requireRcvBufError(t, e, c.wantErr)
			if name != "initial fail" && (discarded != 1 || usedAtDiscard != base+int64(ss2017RcvBufActual-212992)) {
				t.Fatalf("%s: socket must be discarded while reservation still held (discard=%d used=%d)", name, discarded, usedAtDiscard)
			}
			requireUsed(t, base)
			continue
		}
		if e != nil || charge != c.charged || discarded != 0 {
			t.Fatalf("%s: charge=%d err=%v", name, charge, e)
		}
		if name == "already large" && sets != 0 {
			t.Fatal("larger default must not be touched")
		}
		requireUsed(t, base+charge)
		returnSSRcvBuf(charge)
	}
	requireUsed(t, base)
}

func TestSS2017RcvBufBudgetExhaustedAndRecovered(t *testing.T) {
	charge := expectedCharge(t)
	base := ssRcvBufUsed.Load()
	hold := ssRcvBufProcessBudget - base - charge + 1
	if !reserveSSRcvBuf(hold) {
		t.Fatal("cannot pre-reserve")
	}
	port := freePort(t)
	in := rcvbufInbound("rcvbuf-budget", true)
	in.Listen = "127.0.0.1:" + strconv.Itoa(port)
	s, e := Start(rcvbufConfig(in))
	if s != nil {
		closeNow(t, s)
	}
	requireRcvBufError(t, e, "budget")
	requireUsed(t, base+hold)
	requirePortFree(t, port)
	returnSSRcvBuf(hold)
	s, e = Start(rcvbufConfig(in))
	if e != nil {
		t.Fatal("budget did not recover after release:", e)
	}
	requireUsed(t, base+charge)
	closeNow(t, s)
	requireUsed(t, base)
}

func TestSS2017RcvBufPartialStartRollback(t *testing.T) {
	charge := expectedCharge(t)
	base := ssRcvBufUsed.Load()
	// Room for exactly one listener: second enabled listener fails after the first was charged.
	hold := ssRcvBufProcessBudget - base - charge
	if !reserveSSRcvBuf(hold) {
		t.Fatal("cannot pre-reserve")
	}
	p1, p2 := freePort(t), freePort(t)
	for p2 == p1 {
		p2 = freePort(t)
	}
	a, b := rcvbufInbound("rcvbuf-partial", true), rcvbufInbound("rcvbuf-partial", true)
	a.Listen, b.Listen = "127.0.0.1:"+strconv.Itoa(p1), "127.0.0.1:"+strconv.Itoa(p2)
	s, e := Start(rcvbufConfig(a, b))
	if s != nil {
		closeNow(t, s)
	}
	requireRcvBufError(t, e, "budget")
	requireUsed(t, base+hold)
	requirePortFree(t, p1)
	requirePortFree(t, p2)
	returnSSRcvBuf(hold)
	// Later TCP bind failure after an enabled listener was charged.
	busy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	c := inFor("socks5", nil)
	c.Listen = busy.Addr().String()
	s, e = Start(rcvbufConfig(a, c))
	if s != nil || e == nil || e.Error() != "cannot bind inbound listener" {
		t.Fatal("expected TCP bind failure", e)
	}
	requireUsed(t, base)
	requirePortFree(t, p1)
}

func TestSS2017RcvBufConcurrentContention(t *testing.T) {
	charge := expectedCharge(t)
	base := ssRcvBufUsed.Load()
	const room = 3
	hold := ssRcvBufProcessBudget - base - room*charge
	if !reserveSSRcvBuf(hold) {
		t.Fatal("cannot pre-reserve")
	}
	stop := make(chan struct{})
	var over atomic.Int64
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				if v := ssRcvBufUsed.Load(); v > ssRcvBufProcessBudget {
					over.Store(v)
				}
				runtime.Gosched()
			}
		}
	}()
	var mu sync.Mutex
	var servers []*Server
	var wg sync.WaitGroup
	var refused atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, e := Start(rcvbufConfig(rcvbufInbound("rcvbuf-race", true)))
			if e != nil {
				var rb *ssRcvBufError
				if !errors.As(e, &rb) {
					t.Error("unexpected error", e)
				}
				refused.Add(1)
				return
			}
			mu.Lock()
			servers = append(servers, s)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(servers) != room || refused.Load() != 12-room {
		t.Fatalf("admitted %d refused %d, want exactly %d", len(servers), refused.Load(), room)
	}
	requireUsed(t, base+hold+room*charge)
	// Concurrent Close of the same and different Servers releases each charge exactly once.
	for _, s := range servers {
		for range 3 {
			wg.Add(1)
			go func() { defer wg.Done(); closeNow(t, s) }()
		}
	}
	wg.Wait()
	close(stop)
	if over.Load() != 0 {
		t.Fatalf("budget exceeded under contention: %d", over.Load())
	}
	requireUsed(t, base+hold)
	returnSSRcvBuf(hold)
	requireUsed(t, base)
	s, e := Start(rcvbufConfig(rcvbufInbound("rcvbuf-race", true)))
	if e != nil {
		t.Fatal("no recovery after concurrent release:", e)
	}
	closeNow(t, s)
	requireUsed(t, base)
}

func TestSS2017RcvBufSharedAcrossListenersAndServers(t *testing.T) {
	charge := expectedCharge(t)
	base := ssRcvBufUsed.Load()
	n := int((ssRcvBufProcessBudget - base) / charge)
	if n < 1 || n+1 > 64 {
		t.Skip("unexpected listener capacity", n)
	}
	ins := func(k int) []Inbound {
		var v []Inbound
		for range k {
			v = append(v, rcvbufInbound("rcvbuf-shared", true))
		}
		return v
	}
	s, e := Start(rcvbufConfig(ins(n + 1)...))
	if s != nil {
		closeNow(t, s)
	}
	requireRcvBufError(t, e, "budget")
	requireUsed(t, base)
	s, e = Start(rcvbufConfig(append(ins(n), rcvbufInbound("rcvbuf-shared", false))...))
	if e != nil {
		t.Fatal(e)
	}
	requireUsed(t, base+int64(n)*charge)
	if len(s.SSUDPReceiveBuffers()) != n || s.cfg.Inbounds[0].ssRuntime != s.cfg.Inbounds[n].ssRuntime {
		t.Fatal("mixed enabled/default listeners of one identity must share runtime")
	}
	other, e := Start(rcvbufConfig(rcvbufInbound("rcvbuf-other", true)))
	if other != nil {
		closeNow(t, other)
	}
	requireRcvBufError(t, e, "budget")
	closeNow(t, s)
	requireUsed(t, base)
}

func TestSS2017RcvBufRejectedOutsideSS2017(t *testing.T) {
	base := ssRcvBufUsed.Load()
	ss22 := ssIn()
	ss22.SS.UDPRcvBuf2017 = ss2017RcvBufActual
	ss22.Listen = "127.0.0.1:0"
	if e := (&Config{Inbounds: []Inbound{ss22}}).Validate(); e == nil || !strings.Contains(e.Error(), "SS2022") {
		t.Fatal("SS2022 accepted udp_rcvbuf_2017:", e)
	}
	if s, e := Start(rcvbufConfig(ss22)); s != nil || e == nil {
		t.Fatal("SS2022 started with udp_rcvbuf_2017")
	}
	socks := inFor("socks5", nil)
	socks.Listen = "127.0.0.1:0"
	socks.SS = &SSOptions{Method: "aes-128-gcm", Password: "x", UDPRcvBuf2017: ss2017RcvBufActual}
	if e := (&Config{Inbounds: []Inbound{socks}}).Validate(); e == nil || !strings.Contains(e.Error(), "protocol options") {
		t.Fatal("non-SS listener accepted SS receive buffer option")
	}
	for _, v := range []int{-1, 1, 212992, 524288, 1048575, 2097152} {
		in := rcvbufInbound("rcvbuf-values", false)
		in.SS.UDPRcvBuf2017 = v
		if e := (&Config{Inbounds: []Inbound{in}}).Validate(); e == nil || !strings.Contains(e.Error(), "exactly 1048576") {
			t.Fatal("accepted generic tuning value", v, e)
		}
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"old.json": `{"inbounds":[{"protocol":"shadowsocks","listen":"127.0.0.1:0","ss":{"method":"aes-128-gcm","password":"p"}}]}`,
		"new.json": `{"inbounds":[{"protocol":"shadowsocks","listen":"127.0.0.1:0","ss":{"method":"aes-128-gcm","password":"p","udp_rcvbuf_2017":1048576}}]}`,
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		c, e := Load(p)
		if e != nil || (c.Inbounds[0].SS.UDPRcvBuf2017 != 0) != (name == "new.json") {
			t.Fatal(name, e)
		}
	}
	requireUsed(t, base)
}

// Source binding, replay protection, queue bound and idle timeout with the option enabled.
func TestSS2017RcvBufEnabledRegression(t *testing.T) {
	charge := expectedCharge(t)
	base := ssRcvBufUsed.Load()
	fds, _ := os.ReadDir("/proc/self/fd")
	s := startTest(t, rcvbufInbound("rcvbuf-regression", true), func(c *Config) { c.Limits.UDPIdle = Duration(200 * time.Millisecond) })
	requireUsed(t, base+charge)
	target := localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	one, two := localUDP(t), localUDP(t)
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	key := md5.Sum([]byte("rcvbuf-regression"))
	encode := func(saltByte byte, payload string) []byte {
		salt := bytes.Repeat([]byte{saltByte}, 16)
		sub, e := hkdf.Key(sha1.New, key[:], salt, "ss-subkey", 16)
		if e != nil {
			t.Fatal(e)
		}
		block, _ := aes.NewCipher(sub)
		a, _ := cipher.NewGCM(block)
		return append(salt, a.Seal(nil, make([]byte, 12), append(peerAddr(dst, false), []byte(payload)...), nil)...)
	}
	first := encode(31, "one")
	one.WriteToUDP(first, endpoint)
	b, out1 := recvUDP(t, target)
	if string(b) != "one" {
		t.Fatal("first payload")
	}
	two.WriteToUDP(encode(32, "two"), endpoint)
	b, out2 := recvUDP(t, target)
	if string(b) != "two" || out1.String() == out2.String() || s.Stats().UDP != 2 {
		t.Fatal("source identities merged")
	}
	target.WriteToUDP([]byte("reply1"), out1)
	recvUDP(t, one)
	silentUDP(t, two)
	target.WriteToUDP([]byte("reply2"), out2)
	recvUDP(t, two)
	silentUDP(t, one)
	one.WriteToUDP(first, endpoint) // same-source replay
	silentUDP(t, target)
	two.WriteToUDP(first, endpoint) // cross-source replay
	silentUDP(t, target)
	bad := encode(33, "bad")
	bad[len(bad)-1] ^= 1
	one.WriteToUDP(bad, endpoint)
	silentUDP(t, target)
	// Queue bound is unchanged by the socket option.
	dropped := s.Stats().Dropped
	ctx, cancel := context.WithCancel(context.Background())
	q := &udpAssociation{server: s, ctx: ctx, queue: make(chan packet, s.cfg.Limits.UDPQueue)}
	for range s.cfg.Limits.UDPQueue + 3 {
		q.enqueue(packet{payload: []byte("x")})
	}
	cancel()
	if len(q.queue) != s.cfg.Limits.UDPQueue || s.Stats().Dropped-dropped != 3 {
		t.Fatal("association queue bound changed")
	}
	waitFor(t, func() bool { return s.Stats().UDP == 0 }) // idle timeout
	if rcvbufOf(t, s.ssListeners[0].socket) != ss2017RcvBufActual {
		t.Fatal("receive buffer changed during traffic")
	}
	closeNow(t, s)
	requireUsed(t, base)
	target.Close()
	one.Close()
	two.Close()
	waitFor(t, func() bool { f, _ := os.ReadDir("/proc/self/fd"); return len(f) <= len(fds)+1 })
}
