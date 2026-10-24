package route

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// origin is a loopback HTTPS rule-set server whose response is scripted.
type origin struct {
	srv  *httptest.Server
	mu   sync.Mutex
	body []byte
	mode string // "", "500", "huge", "html", "block"
	reqs []time.Time
	hits atomic.Int64
	fail atomic.Int64 // answer 503 to this many requests first
	ver  atomic.Int64 // mode "ver": a new version per request
}

func newOrigin(t *testing.T, body string) *origin {
	o := &origin{body: []byte(body)}
	o.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		o.mu.Lock()
		o.reqs = append(o.reqs, time.Now())
		mode, body := o.mode, o.body
		o.mu.Unlock()
		if o.fail.Add(-1) >= 0 {
			http.Error(w, "unavailable", 503)
			return
		}
		switch mode {
		case "ver":
			fmt.Fprintf(w, "+.v%d.example\nconst.example\n", o.ver.Add(1))
		case "500":
			http.Error(w, "boom", 500)
		case "huge":
			w.Write(bytes.Repeat([]byte("a.example\n"), 1000))
		case "html":
			w.Write([]byte("<html><body>maintenance</body></html>\n"))
		case "block":
			<-r.Context().Done()
		default:
			w.Write(body)
		}
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *origin) set(mode, body string) {
	o.mu.Lock()
	o.mode = mode
	if body != "" {
		o.body = []byte(body)
	}
	o.mu.Unlock()
}

func (o *origin) times() []time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]time.Time(nil), o.reqs...)
}

type dialRecorder struct {
	calls atomic.Int64
	mu    sync.Mutex
	vias  []string
}

func (d *dialRecorder) first() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.vias) == 0 {
		return ""
	}
	return d.vias[0]
}

func (d *dialRecorder) dial(via string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	d.mu.Lock()
	d.vias = append(d.vias, via)
	d.mu.Unlock()
	if via == "broken" {
		return nil, errors.New("unknown outbound")
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d.calls.Add(1)
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}, nil
}

// remoteEngine builds an engine trusting the origin's test certificate with
// short test timings (interval/backoff are unexported hooks; Validate keeps
// the 1m minimum for real configurations).
func remoteEngine(t *testing.T, o Options, org *origin, dr *dialRecorder, ev *eventLog, interval, backoff time.Duration) *Engine {
	t.Helper()
	e, err := NewEngine(o, dr.dial, ev.sink)
	if err != nil {
		t.Fatal(err)
	}
	if org != nil {
		pool := x509.NewCertPool()
		pool.AddCert(org.srv.Certificate())
		e.rootCAs = pool
	}
	e.backoffBase = backoff
	e.fetchTimeout = 5 * time.Second
	for _, s := range e.sources {
		s.interval = interval
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func readFile(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func noTmp(t *testing.T, p string) {
	if _, err := os.Stat(p + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary file left behind", err)
	}
}

func TestRemoteFirstDownloadAtomicWriteViaDial(t *testing.T) {
	org := newOrigin(t, "+.remote.example\n")
	p := filepath.Join(t.TempDir(), "sub", "dir", "remote.txt") // parent created on demand
	dr := &dialRecorder{}
	ev := &eventLog{}
	e := remoteEngine(t, Options{
		Rules:    []Rule{{RuleSet: "r", Outbound: "P"}},
		RuleSets: []RuleSetOptions{{Name: "r", Format: "domain", Path: p, URL: org.srv.URL + "/r.txt?token=secret", Via: "chain-a"}},
	}, org, dr, ev, time.Hour, time.Minute)
	if d, _ := decideHost(t, e, "x.remote.example", 1, &fakeDNS{ips: addrs("192.0.2.1")}); d.Kind != Direct {
		t.Fatal("rule set should be empty before Start", d)
	}
	e.Start(context.Background())
	waitFor(t, 5*time.Second, "rule_set_loaded", func() bool { return ev.count("rule_set_loaded", "name", "r") == 1 })
	if d, _ := decideHost(t, e, "x.remote.example", 1, &fakeDNS{}); d.Kind != Proxy || d.Outbound != "P" {
		t.Fatal("downloaded set not active", d)
	}
	if readFile(t, p) != "+.remote.example\n" {
		t.Fatal("file content")
	}
	noTmp(t, p)
	if dr.calls.Load() == 0 || dr.first() != "chain-a" {
		t.Fatal("download did not use injected dial for via", dr.calls.Load(), dr.first())
	}
	for _, x := range ev.all() {
		if strings.Contains(strings.Join(x, " "), "secret") || strings.Contains(strings.Join(x, " "), "127.0.0.1") {
			t.Fatal("event leaks url", x)
		}
	}
	// Fresh file + 1h interval: a second engine on the same path does not refetch immediately.
	before := org.hits.Load()
	ev2 := &eventLog{}
	e2 := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "r", Format: "domain", Path: p, URL: org.srv.URL + "/r.txt"}}}, org, dr, ev2, time.Hour, time.Minute)
	e2.Start(context.Background())
	time.Sleep(200 * time.Millisecond)
	if org.hits.Load() != before || ev2.count("rule_set_loaded", "name", "r", "entries", "1") != 1 {
		t.Fatal("fresh local file should be used without refetch", org.hits.Load()-before, ev2.all())
	}
}

func TestRemoteIntervalRefresh(t *testing.T) {
	org := newOrigin(t, "DOMAIN,v1.example\n")
	p := filepath.Join(t.TempDir(), "c.txt")
	dr := &dialRecorder{}
	ev := &eventLog{}
	e := remoteEngine(t, Options{
		Rules:    []Rule{{RuleSet: "c", Action: "reject"}},
		RuleSets: []RuleSetOptions{{Name: "c", Format: "classical", Path: p, URL: org.srv.URL + "/c"}},
	}, org, dr, ev, 150*time.Millisecond, time.Minute)
	e.Start(context.Background())
	waitFor(t, 5*time.Second, "v1", func() bool {
		d, _ := decideHost(t, e, "v1.example", 1, &fakeDNS{ips: addrs("192.0.2.1")})
		return d.Kind == Reject
	})
	org.set("", "DOMAIN,v2.example\n")
	waitFor(t, 5*time.Second, "v2 after interval", func() bool {
		d, _ := decideHost(t, e, "v2.example", 1, &fakeDNS{ips: addrs("192.0.2.1")})
		return d.Kind == Reject
	})
	if d, _ := decideHost(t, e, "v1.example", 1, &fakeDNS{ips: addrs("192.0.2.1")}); d.Kind != Direct {
		t.Fatal("old content still active", d)
	}
	waitFor(t, 2*time.Second, "file v2", func() bool { return readFile(t, p) == "DOMAIN,v2.example\n" })
	ts := org.times()
	for i := 1; i < len(ts); i++ {
		if gap := ts[i].Sub(ts[i-1]); gap < 140*time.Millisecond {
			t.Fatal("refresh faster than interval", gap)
		}
	}
	t.Logf("refreshes=%d at ~150ms interval", len(ts))
}

func TestRemoteFailuresKeepOldDataAndFile(t *testing.T) {
	org := newOrigin(t, "")
	org.set("500", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "keep.txt")
	old := "keep.example\n"
	os.WriteFile(p, []byte(old), 0o644)
	stale := time.Now().Add(-2 * time.Hour)
	os.Chtimes(p, stale, stale) // older than interval: refresh immediately at Start
	dr := &dialRecorder{}
	ev := &eventLog{}
	e := remoteEngine(t, Options{
		Rules:    []Rule{{RuleSet: "k", Action: "reject"}},
		RuleSets: []RuleSetOptions{{Name: "k", Format: "domain", Path: p, URL: org.srv.URL + "/k", MaxBytes: 4096}},
	}, org, dr, ev, time.Hour, 30*time.Millisecond)
	if ev.count("rule_set_loaded", "name", "k", "entries", "1") != 1 {
		t.Fatal("local file not loaded first", ev.all())
	}
	check := func(stage string) {
		t.Helper()
		if d, _ := decideHost(t, e, "keep.example", 1, &fakeDNS{}); d.Kind != Reject {
			t.Fatal(stage, "old data lost", d)
		}
		if readFile(t, p) != old {
			t.Fatal(stage, "old file replaced")
		}
		noTmp(t, p)
	}
	e.Start(context.Background())
	waitFor(t, 5*time.Second, "http_status failure", func() bool { return ev.count("rule_set_update_failed", "name", "k", "class", "http_status") >= 1 })
	check("500")
	org.set("huge", "")
	waitFor(t, 5*time.Second, "too_large failure", func() bool { return ev.count("rule_set_update_failed", "name", "k", "class", "too_large") >= 1 })
	check("huge")
	org.set("html", "")
	waitFor(t, 5*time.Second, "parse failure", func() bool { return ev.count("rule_set_update_failed", "name", "k", "class", "parse") >= 1 })
	check("html")
	e.Close()
	check("closed")
	// Untrusted certificate (no test root): tls failure, data kept.
	ev2 := &eventLog{}
	org.set("", "new.example\n")
	e2 := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "k", Format: "domain", Path: p, URL: org.srv.URL + "/k"}}}, nil, dr, ev2, time.Hour, time.Minute)
	e2.Start(context.Background())
	waitFor(t, 5*time.Second, "tls failure", func() bool { return ev2.count("rule_set_update_failed", "name", "k", "class", "tls") == 1 })
	e2.Close()
	if readFile(t, p) != old {
		t.Fatal("untrusted origin replaced file")
	}
	// Via that cannot provide a dialer.
	ev3 := &eventLog{}
	e3 := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "k", Format: "domain", Path: p, URL: org.srv.URL + "/k", Via: "broken"}}}, org, dr, ev3, time.Hour, time.Minute)
	e3.Start(context.Background())
	waitFor(t, 5*time.Second, "dial failure", func() bool { return ev3.count("rule_set_update_failed", "name", "k", "class", "dial") == 1 })
	e3.Close()
	t.Logf("failure events: %v", ev.all())
}

func TestRemoteEmptyStartBackoffThenSuccess(t *testing.T) {
	org := newOrigin(t, "198.51.100.0/24\n")
	org.fail.Store(3)
	p := filepath.Join(t.TempDir(), "ip.txt")
	dr := &dialRecorder{}
	ev := &eventLog{}
	base := 40 * time.Millisecond
	e := remoteEngine(t, Options{
		Rules:    []Rule{{RuleSet: "ip", Action: "reject"}},
		RuleSets: []RuleSetOptions{{Name: "ip", Format: "ipcidr", Path: p, URL: org.srv.URL + "/ip"}},
	}, org, dr, ev, time.Hour, base)
	if len(ev.all()) != 0 {
		t.Fatal("missing file with url should start silently empty", ev.all())
	}
	e.Start(context.Background())
	if d := decideIP(t, e, "198.51.100.1", 1); d.Kind != Direct {
		t.Fatal("empty set should not match", d)
	}
	waitFor(t, 10*time.Second, "loaded after retries", func() bool { return ev.count("rule_set_loaded", "name", "ip") == 1 })
	if ev.count("rule_set_update_failed", "name", "ip", "class", "http_status") != 3 {
		t.Fatal("expected 3 failures", ev.all())
	}
	if d := decideIP(t, e, "198.51.100.1", 1); d.Kind != Reject {
		t.Fatal("not active after retry", d)
	}
	ts := org.times()
	if len(ts) < 4 {
		t.Fatal("requests", len(ts))
	}
	var gaps []time.Duration
	for i := 1; i < 4; i++ {
		gap := ts[i].Sub(ts[i-1])
		gaps = append(gaps, gap.Round(time.Millisecond))
		if want := base << (i - 1); gap < want-5*time.Millisecond {
			t.Fatalf("retry %d after %v, want >= %v (exponential backoff)", i, gap, want)
		}
	}
	if readFile(t, p) != "198.51.100.0/24\n" {
		t.Fatal("file")
	}
	t.Logf("backoff gaps with base %v: %v", base, gaps)
}

func TestRemoteGeoIPDownload(t *testing.T) {
	db := testMMDB(t)
	org := newOrigin(t, "")
	org.mu.Lock()
	org.body = db
	org.mu.Unlock()
	p := filepath.Join(t.TempDir(), "country.mmdb")
	dr := &dialRecorder{}
	ev := &eventLog{}
	e := remoteEngine(t, Options{
		Rules: []Rule{{GeoIP: "CN", Outbound: "cn"}},
		GeoIP: &GeoIPOptions{Path: p, URL: org.srv.URL + "/country.mmdb", Via: "g"},
	}, org, dr, ev, time.Hour, 20*time.Millisecond)
	e.Start(context.Background())
	waitFor(t, 5*time.Second, "geoip_loaded", func() bool { return ev.count("geoip_loaded") == 1 })
	if d := decideIP(t, e, "1.0.1.1", 1); d.Outbound != "cn" {
		t.Fatal(d)
	}
	if !bytes.Equal([]byte(readFile(t, p)), db) || dr.first() != "g" {
		t.Fatal("geoip file/via")
	}
	e.Close()
	// Corrupt replacement is refused; old database file stays.
	org.set("html", "")
	stale := time.Now().Add(-2 * time.Hour)
	os.Chtimes(p, stale, stale)
	ev2 := &eventLog{}
	e2 := remoteEngine(t, Options{Rules: []Rule{{GeoIP: "CN", Outbound: "cn"}}, GeoIP: &GeoIPOptions{Path: p, URL: org.srv.URL + "/country.mmdb"}}, org, dr, ev2, time.Hour, time.Minute)
	e2.Start(context.Background())
	waitFor(t, 5*time.Second, "geoip parse failure", func() bool { return ev2.count("geoip_update_failed", "class", "parse") == 1 })
	if d := decideIP(t, e2, "1.0.1.1", 1); d.Outbound != "cn" || !bytes.Equal([]byte(readFile(t, p)), db) {
		t.Fatal("geoip old data lost")
	}
}

func TestRemoteLifecycleAndConcurrentDecide(t *testing.T) {
	baseline := runtime.NumGoroutine()
	org := newOrigin(t, "")
	org.set("block", "")
	p := filepath.Join(t.TempDir(), "b.txt")
	dr := &dialRecorder{}
	ev := &eventLog{}
	e := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "b", Format: "domain", Path: p, URL: org.srv.URL + "/b"}}}, org, dr, ev, time.Hour, time.Minute)
	e.Start(context.Background())
	e.Start(context.Background()) // idempotent
	waitFor(t, 5*time.Second, "request in flight", func() bool { return org.hits.Load() == 1 })
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked by in-flight download")
	}
	if n := len(ev.all()); n != 0 {
		t.Fatal("cancellation reported as failure", ev.all())
	}
	e.Start(context.Background()) // after Close: no-op
	e.Close()
	(&Engine{}).Close() // Close without Start

	// Start ctx cancellation also stops refresh.
	ctx, cancel := context.WithCancel(context.Background())
	e2 := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "b", Format: "domain", Path: p, URL: org.srv.URL + "/b"}}}, org, dr, ev, time.Hour, time.Minute)
	e2.Start(ctx)
	waitFor(t, 5*time.Second, "second request", func() bool { return org.hits.Load() == 2 })
	cancel()
	e2.Close()

	// Concurrent Decide while the set is replaced every few milliseconds.
	org.set("ver", "")
	ev3 := &eventLog{}
	e3 := remoteEngine(t, Options{Rules: []Rule{{RuleSet: "b", Action: "reject"}}, RuleSets: []RuleSetOptions{{Name: "b", Format: "domain", Path: p, URL: org.srv.URL + "/b"}}}, org, dr, ev3, 2*time.Millisecond, time.Millisecond)
	e3.Start(context.Background())
	var wg sync.WaitGroup
	var bad atomic.Int64
	stop := make(chan struct{})
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				loaded := ev3.count("rule_set_loaded") > 0 // emitted after the swap
				d, err := e3.Decide(context.Background(), Metadata{Network: "tcp", Host: "const.example", Port: 1}, (&fakeDNS{ips: addrs("192.0.2.1")}).resolve)
				if err != nil || loaded && d.Kind != Reject {
					bad.Add(1)
				}
			}
		}()
	}
	waitFor(t, 10*time.Second, "several swaps", func() bool { return ev3.count("rule_set_loaded") >= 20 })
	close(stop)
	wg.Wait()
	e3.Close()
	if bad.Load() != 0 {
		t.Fatal("inconsistent decisions during swaps", bad.Load())
	}
	org.srv.Close()
	org.srv.CloseClientConnections()
	waitFor(t, 5*time.Second, "goroutines to return to baseline", func() bool { return runtime.NumGoroutine() <= baseline+2 })
	t.Logf("swaps=%d goroutines baseline=%d now=%d", ev3.count("rule_set_loaded"), baseline, runtime.NumGoroutine())
}
