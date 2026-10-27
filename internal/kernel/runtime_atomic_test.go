package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

func TestRuntimeAtomicBusyRollback(t *testing.T) {
	for _, kind := range []string{"api", "stats"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			base := selectCfg(filepath.Join(dir, "old.stats.json"), "", "direct", "reject", "h")
			base.API = &APIOptions{Socket: filepath.Join(dir, "old.sock")}
			next := base
			s := startReloadable(t, base, &next)
			if e := s.Select("g", "h"); e != nil {
				t.Fatal(e)
			}
			next = selectCfg(filepath.Join(dir, "new.stats.json"), "", "direct", "reject", "h")
			next.API = &APIOptions{Socket: filepath.Join(dir, "new.sock")}
			next.Inbounds[0].Users = []User{{Username: "changed", Password: "changed"}}
			stage := "stats"
			if kind == "api" {
				ln, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer ln.Close()
				next.API.Listen = ln.Addr().String()
				next.API.Secret = "candidate-secret"
				stage = "api"
			} else {
				release, e := stats.Lock(next.Stats.File)
				if e != nil {
					t.Fatal(e)
				}
				defer release()
			}
			_, e := s.Reload("atomic-test")
			var re *ReloadError
			if !errors.As(e, &re) || re.Stage != stage {
				t.Fatalf("want %s refusal/running unchanged, got %v generation=%d", stage, e, s.StatsView().Reload.Generation)
			}
			if s.current().id != 1 || len(s.current().cfg.Inbounds[0].Users) != 0 {
				t.Fatal("forwarding changed")
			}
			if s.persistedPath() != base.Stats.File {
				t.Fatal("stats path changed")
			}
			if release, e := stats.Lock(base.Stats.File); e == nil {
				release()
				t.Fatal("old lock lost")
			}
			if cur, _ := currentOf(t, s, "g"); cur != "h" {
				t.Fatal("selection lost")
			}
		})
	}
}

func atomicClient(t *testing.T, socket string) *http.Client {
	t.Helper()
	tr := &http.Transport{}
	if socket != "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}
func atomicRequest(t *testing.T, c *http.Client, url, method, secret string) (int, []byte) {
	t.Helper()
	r, e := http.NewRequest(method, url, nil)
	if e != nil {
		t.Fatal(e)
	}
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	res, e := c.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, b
}
func TestRuntimeAtomicAPIRequestsAndRotation(t *testing.T) {
	dir := t.TempDir()
	base := socksCfg("127.0.0.1:0")
	a := reloadPort(t)
	base.API = &APIOptions{Socket: filepath.Join(dir, "a.sock"), Listen: a, Secret: "old-secret-0123456789"}
	next := base
	s := startReloadable(t, base, &next)
	client := atomicClient(t, "")
	url := "http://" + a + "/v1/version"
	// Pin a real HTTP/1.1 keepalive TCP connection across a same-address rotation.
	var first, second net.Conn
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+base.API.Secret)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { first = i.Conn }}))
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	next = base
	next.API = &APIOptions{Socket: base.API.Socket, Listen: a, Secret: "new-secret-0123456789"}
	if _, e = s.Reload("rotate"); e != nil {
		t.Fatal(e)
	}
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+base.API.Secret)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { second = i.Conn }}))
	res, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if first != second || res.StatusCode != 401 {
		t.Fatalf("old secret on same keepalive: same=%v status=%d", first == second, res.StatusCode)
	}
	if code, _ := atomicRequest(t, client, url, "GET", next.API.Secret); code != 200 {
		t.Fatal(code)
	}
	// The reload is really executing inside the endpoint being retired.
	oldSock := next.API.Socket
	oldClient := atomicClient(t, oldSock)
	b := reloadPort(t)
	next.API = &APIOptions{Socket: filepath.Join(dir, "b.sock"), Listen: b, Secret: "third-secret-012345"}
	if code, body := atomicRequest(t, oldClient, "http://unix/v1/reload", "POST", ""); code != 200 || !bytes.Contains(body, []byte(`"generation": 3`)) {
		t.Fatalf("old reload response %d %s", code, body)
	}
	if _, e = os.Lstat(oldSock); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("old socket not retired", e)
	}
	if code, _ := atomicRequest(t, atomicClient(t, next.API.Socket), "http://unix/v1/stats", "GET", ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ := atomicRequest(t, client, "http://"+b+"/v1/version", "GET", next.API.Secret); code != 200 {
		t.Fatal(code)
	}
	// Disable through the TCP endpoint itself, then enable and rotate rapidly.
	oldAPI := *next.API
	disabled := false
	next.API = &APIOptions{Enabled: &disabled}
	if code, _ := atomicRequest(t, client, "http://"+b+"/v1/reload", "POST", oldAPI.Secret); code != 200 {
		t.Fatal(code)
	}
	if l, e := net.Listen("tcp", b); e != nil {
		t.Fatal("disabled endpoint still bound", e)
	} else {
		l.Close()
	}
	for i := 0; i < 24; i++ {
		next.API = &APIOptions{Socket: filepath.Join(dir, fmt.Sprintf("%d.sock", i%2)), Listen: a, Secret: fmt.Sprintf("secret-%024d", i)}
		if _, e = s.Reload("rapid"); e != nil {
			t.Fatal(e)
		}
		if code, _ := atomicRequest(t, atomicClient(t, next.API.Socket), "http://unix/v1/version", "GET", ""); code != 200 {
			t.Fatal(code)
		}
	}
	// The latest socket survives all asynchronous predecessor shutdowns.
	if code, _ := atomicRequest(t, atomicClient(t, next.API.Socket), "http://unix/v1/version", "GET", ""); code != 200 {
		t.Fatal(code)
	}
}

func TestRuntimeAtomicPreparedNoServeOrOverwrite(t *testing.T) {
	dir := t.TempDir()
	base := selectCfg(filepath.Join(dir, "old.stats.json"), "", "direct", "reject", "h")
	base.API = &APIOptions{Socket: filepath.Join(dir, "old.sock")}
	next := base
	s := startReloadable(t, base, &next)
	s.reg.Total.AddUp(123)
	if e := s.saveStats(); e != nil {
		t.Fatal(e)
	}
	next = selectCfg(filepath.Join(dir, "new.stats.json"), "", "direct", "reject", "h")
	next.API = &APIOptions{Socket: filepath.Join(dir, "new.sock")}
	// A legal preexisting target must not be overwritten or loaded in prepare.
	target := stats.New(nil, nil, nil, nil, time.Now())
	target.Total.AddUp(99999)
	if e := target.Save(next.Stats.File, time.Now()); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(next.Stats.File)
	info, _ := os.Stat(next.Stats.File)
	k := s.core
	k.reloadMu.Lock()
	g, p, e := k.prepare(next, s.current())
	if e != nil {
		k.reloadMu.Unlock()
		t.Fatal(e)
	}
	b, _ := os.ReadFile(next.Stats.File)
	after, _ := os.Stat(next.Stats.File)
	if !bytes.Equal(before, b) || !os.SameFile(info, after) {
		t.Fatal("prepare replaced target")
	}
	conn, e := net.DialTimeout("unix", next.API.Socket, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	conn.Write([]byte("GET /v1/version HTTP/1.1\r\nHost: unix\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var one [1]byte
	if _, e = conn.Read(one[:]); e == nil {
		t.Fatal("candidate served before commit")
	}
	conn.Close()
	p.abort()
	g.rt.close()
	g.dns.close()
	k.genSeq.Add(^uint64(0))
	k.reloadMu.Unlock()
	after, _ = os.Stat(next.Stats.File)
	b, _ = os.ReadFile(next.Stats.File)
	if !bytes.Equal(before, b) || !os.SameFile(info, after) {
		t.Fatal("abort changed target")
	}
	if r, e := stats.Lock(next.Stats.File); e != nil {
		t.Fatal("candidate lock leaked", e)
	} else {
		r()
	}
	if _, e = os.Lstat(next.API.Socket); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("candidate socket leaked")
	}
	if code, _ := atomicRequest(t, atomicClient(t, base.API.Socket), "http://unix/v1/version", "GET", ""); code != 200 {
		t.Fatal(code)
	}
}

func TestRuntimeAtomicStateFailuresAndContinuation(t *testing.T) {
	for _, kind := range []string{"directory", "readonly-file", "readonly-dir", "select-directory", "parent-file", "socket-file", "foreign-socket", "stale-socket"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			base := selectCfg(filepath.Join(dir, "old.stats.json"), "", "direct", "reject", "h")
			base.API = &APIOptions{Socket: filepath.Join(dir, "old.sock")}
			next := base
			s := startReloadable(t, base, &next)
			if e := s.Select("g", "h"); e != nil {
				t.Fatal(e)
			}
			s.reg.Total.AddUp(12345)
			s.saveStats()
			oldBytes, _ := os.ReadFile(base.Stats.File)
			oldInfo, _ := os.Stat(base.Stats.File)
			oldSel, _ := os.ReadFile(selectStatePath(base.Stats.File))
			next = selectCfg(filepath.Join(dir, "new.stats.json"), "", "direct", "reject", "h")
			next.API = &APIOptions{Socket: filepath.Join(dir, "new.sock")}
			path := next.Stats.File
			stage := "stats"
			switch kind {
			case "directory":
				os.Mkdir(path, 0700)
			case "readonly-file":
				os.WriteFile(path, []byte("do-not-touch"), 0400)
			case "readonly-dir":
				d := filepath.Join(dir, "readonly")
				os.Mkdir(d, 0500)
				defer os.Chmod(d, 0700)
				next.Stats.File = filepath.Join(d, "x.stats.json")
				path = d
			case "select-directory":
				path = selectStatePath(path)
				os.Mkdir(path, 0700)
			case "parent-file":
				path = filepath.Join(dir, "parent")
				os.WriteFile(path, []byte("parent"), 0600)
				next.Stats.File = filepath.Join(path, "x.stats.json")
			case "socket-file":
				path = next.API.Socket
				os.WriteFile(path, []byte("not-a-socket"), 0640)
				stage = "api"
			case "stale-socket":
				path = next.API.Socket
				l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if e != nil {
					t.Fatal(e)
				}
				l.SetUnlinkOnClose(false)
				l.Close()
				stage = "api"
			case "foreign-socket":
				path = next.API.Socket
				l, e := net.Listen("unix", path)
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				stage = "api"
			}
			fi, _ := os.Lstat(path)
			data, _ := os.ReadFile(path)
			_, e := s.Reload("failure")
			var re *ReloadError
			if !errors.As(e, &re) || re.Stage != stage {
				t.Fatalf("stage %s got %v", stage, e)
			}
			af, _ := os.Lstat(path)
			ad, _ := os.ReadFile(path)
			if !os.SameFile(fi, af) || fi.Mode() != af.Mode() || !bytes.Equal(data, ad) {
				t.Fatal("foreign target changed")
			}
			nb, _ := os.ReadFile(base.Stats.File)
			ni, _ := os.Stat(base.Stats.File)
			ns, _ := os.ReadFile(selectStatePath(base.Stats.File))
			if !bytes.Equal(oldBytes, nb) || !os.SameFile(oldInfo, ni) || !bytes.Equal(oldSel, ns) {
				t.Fatal("old files changed on abort")
			}
			if s.current().id != 1 || s.persistedPath() != base.Stats.File || s.reg.Snapshot().Total.Up != 12345 {
				t.Fatal("old runtime changed")
			}
			if cur, _ := currentOf(t, s, "g"); cur != "h" {
				t.Fatal(cur)
			}
			if r, e := stats.Lock(base.Stats.File); e == nil {
				r()
				t.Fatal("old lock lost")
			}
			if code, _ := atomicRequest(t, atomicClient(t, base.API.Socket), "http://unix/v1/version", "GET", ""); code != 200 {
				t.Fatal(code)
			}
			leaks, _ := filepath.Glob(filepath.Join(dir, ".kat-reload-*"))
			if len(leaks) != 0 {
				t.Fatal("staging leak", leaks)
			}
		})
	}
	// Success overwrites a legal target with this process's total and choices.
	dir := t.TempDir()
	base := selectCfg(filepath.Join(dir, "a.stats.json"), "", "direct", "reject", "h")
	next := base
	s := startReloadable(t, base, &next)
	s.Select("g", "h")
	s.reg.Total.AddUp(77)
	target := stats.New(nil, nil, nil, nil, time.Now())
	target.Total.AddUp(999999)
	newPath := filepath.Join(dir, "b.stats.json")
	target.Save(newPath, time.Now())
	next = selectCfg(newPath, "", "direct", "reject", "h")
	if r, e := s.Reload("switch"); e != nil || r.Generation != 2 {
		t.Fatal(r, e)
	}
	if s.reg.Snapshot().Total.Up != 77 {
		t.Fatal("loaded target cumulative")
	}
	var disk struct{ Total stats.Traffic }
	b, _ := os.ReadFile(newPath)
	json.Unmarshal(b, &disk)
	if disk.Total.Up != 77 {
		t.Fatal("wrong saved total", disk.Total)
	}
	if cur, _ := currentOf(t, s, "g"); cur != "h" {
		t.Fatal(cur)
	}
	if r, e := stats.Lock(base.Stats.File); e != nil {
		t.Fatal("old lock not released", e)
	} else {
		r()
	}
	if r, e := stats.Lock(newPath); e == nil {
		r()
		t.Fatal("new lock not held")
	}
	off := false
	next.Stats = &StatsOptions{File: newPath, Persist: &off}
	if _, e := s.Reload("off"); e != nil {
		t.Fatal(e)
	}
	if s.persistedPath() != "" {
		t.Fatal("persist off")
	}
	if r, e := stats.Lock(newPath); e == nil {
		r()
		t.Fatal("persist off must keep select lock")
	}
	s.reg.Total.AddUp(1)
	next.Stats = &StatsOptions{File: newPath}
	if _, e := s.Reload("on"); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(newPath)
	json.Unmarshal(b, &disk)
	if disk.Total.Up != 78 {
		t.Fatal(disk.Total)
	}
	// Rotate back and forth without reloading stale totals or selections.
	for i := 0; i < 12; i++ {
		p := base.Stats.File
		if i%2 == 1 {
			p = newPath
		}
		next.Stats = &StatsOptions{File: p}
		if _, e := s.Reload("cycle"); e != nil {
			t.Fatal(e)
		}
	}
	if s.reg.Snapshot().Total.Up != 78 {
		t.Fatal("rotation changed count")
	}
}

func TestRuntimeAtomicRenameAbortAndConcurrentSavers(t *testing.T) {
	dir := t.TempDir()
	base := selectCfg(filepath.Join(dir, "old.stats.json"), "", "direct", "reject", "h")
	base.API = &APIOptions{Socket: filepath.Join(dir, "old.sock")}
	next := base
	s := startReloadable(t, base, &next)
	s.Select("g", "h")
	s.reg.Total.AddUp(7)
	s.saveStats()
	old, _ := os.ReadFile(base.Stats.File)
	oldInfo, _ := os.Stat(base.Stats.File)
	next = selectCfg(filepath.Join(dir, "new.stats.json"), "", "direct", "reject", "h")
	next.API = &APIOptions{Socket: filepath.Join(dir, "new.sock")}
	k := s.core
	k.reloadMu.Lock()
	g, p, e := k.prepare(next, s.current())
	if e != nil {
		t.Fatal(e)
	}
	// A real target obstacle arising after prepare exercises undo after the
	// new select file was already renamed; no mock rename implementation.
	if e = os.Mkdir(next.Stats.File, 0700); e != nil {
		t.Fatal(e)
	}
	if e = k.commit(g, p); e == nil {
		t.Fatal("late filesystem obstacle accepted")
	}
	p.abort()
	g.rt.close()
	g.dns.close()
	k.genSeq.Add(^uint64(0))
	k.reloadMu.Unlock()
	b, _ := os.ReadFile(base.Stats.File)
	fi, _ := os.Stat(base.Stats.File)
	if !bytes.Equal(old, b) || !os.SameFile(fi, oldInfo) {
		t.Fatal("rename abort changed old")
	}
	if _, e = os.Lstat(selectStatePath(next.Stats.File)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("installed select not undone")
	}
	os.Remove(next.Stats.File)
	// Repeat with a legal existing select target: undo must restore its inode.
	selectPath := selectStatePath(next.Stats.File)
	os.WriteFile(selectPath, []byte("foreign-selection"), 0640)
	selInfo, _ := os.Stat(selectPath)
	k.reloadMu.Lock()
	g, p, e = k.prepare(next, s.current())
	if e != nil {
		t.Fatal(e)
	}
	os.Mkdir(next.Stats.File, 0700)
	if e = k.commit(g, p); e == nil {
		t.Fatal("expected late failure")
	}
	p.abort()
	g.rt.close()
	g.dns.close()
	k.genSeq.Add(^uint64(0))
	k.reloadMu.Unlock()
	b, _ = os.ReadFile(selectPath)
	fi, _ = os.Stat(selectPath)
	if string(b) != "foreign-selection" || !os.SameFile(fi, selInfo) || fi.Mode().Perm() != 0640 {
		t.Fatal("existing select inode not restored")
	}
	os.Remove(next.Stats.File)
	var wg sync.WaitGroup
	for j := 0; j < 3; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			for i := 0; i < 35; i++ {
				switch j {
				case 0:
					s.saveStats()
				case 1:
					apiBackend{k}.ResetStats()
				case 2:
					s.Select("g", []string{"direct", "h"}[i%2])
				}
			}
		}(j)
	}
	for i := 0; i < 30; i++ {
		path := filepath.Join(dir, fmt.Sprintf("cycle-%d.stats.json", i%2))
		next = selectCfg(path, "", "direct", "reject", "h")
		next.API = &APIOptions{Socket: filepath.Join(dir, fmt.Sprintf("cycle-%d.sock", i%2))}
		if _, e := s.Reload("concurrent"); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
	if s.current().id != 31 {
		t.Fatal("failed candidates consumed generation", s.current().id)
	}
	for _, glob := range []string{".kat-reload-*", "*.tmp-*"} {
		ls, _ := filepath.Glob(filepath.Join(dir, glob))
		if len(ls) > 0 {
			t.Fatal("temporary leak", ls)
		}
	}
}

func TestRuntimeAtomicReversePrepareAbort(t *testing.T) {
	dir := t.TempDir()
	base := selectCfg(filepath.Join(dir, "a.stats.json"), "", "direct", "reject", "h")
	next := base
	s := startReloadable(t, base, &next)
	s.reg.Total.AddUp(16)
	s.saveStats()
	before, _ := os.ReadFile(base.Stats.File)
	inode, _ := os.Stat(base.Stats.File)
	next = selectCfg(filepath.Join(dir, "b.stats.json"), "", "direct", "reject", "h")
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	next.API = &APIOptions{Socket: filepath.Join(dir, "candidate.sock"), Listen: l.Addr().String(), Secret: "candidate-secret"}
	// Exercise inverse resource ownership explicitly: state is ready before API
	// preparation fails. This uses the same production prepare/abort methods.
	s.reloadMu.Lock()
	state, e := s.prepareState(&next, s.selections)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.prepareAPI(&next); e == nil {
		t.Fatal("busy API accepted")
	}
	state.abort()
	s.reloadMu.Unlock()
	b, _ := os.ReadFile(base.Stats.File)
	fi, _ := os.Stat(base.Stats.File)
	if !bytes.Equal(before, b) || !os.SameFile(inode, fi) {
		t.Fatal("old file touched")
	}
	if r, e := stats.Lock(next.Stats.File); e != nil {
		t.Fatal("new lock leaked", e)
	} else {
		r()
	}
	for _, path := range []string{next.Stats.File, selectStatePath(next.Stats.File), next.API.Socket} {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("candidate leaked", path)
		}
	}
	if r, e := stats.Lock(base.Stats.File); e == nil {
		r()
		t.Fatal("old lock lost")
	}
}

func TestRuntimeAtomicStartupWarningsAndProviderReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.stats.json")
	release, e := stats.Lock(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	busy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	base := socksCfg("127.0.0.1:0")
	base.Stats = &StatsOptions{File: path}
	base.API = &APIOptions{Socket: filepath.Join(dir, "a.sock"), Listen: busy.Addr().String(), Secret: "startup-secret-012345"}
	next := base
	s := startReloadable(t, base, &next)
	if s.current().id != 1 || s.persistedPath() != "" {
		t.Fatal("startup changed to hard-failure")
	}
	if code, _ := atomicRequest(t, atomicClient(t, base.API.Socket), "http://unix/v1/version", "GET", ""); code != 200 {
		t.Fatal("startup partial Unix unavailable")
	}
	s.SetConfigLoader(func() (Config, error) { return Config{}, errors.New("half-written config must not be read") })
	if _, e := s.reload("provider", false); e == nil {
		t.Fatal("provider reload must obey API transaction")
	}
	busy.Close()
	release()
	release = nil
	if r, e := s.reload("provider", false); e != nil || r.Generation != 2 {
		t.Fatal("provider rebuild read loader or failed", r, e)
	}
	if s.persistedPath() != path {
		t.Fatal("reload did not recover startup stats lock")
	}
}
