package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

func TestInstancePaths(t *testing.T) {
	for in, want := range map[string]string{"/etc/kat/ss.json": "ss", "/etc/kat/anytls.json": "anytls", "/x/my config!.json": "my_config_", "/x/.json": "kat", "a.b.json": "a.b"} {
		if got := instanceName(in); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
	a, b := defaultPaths("/etc/kat/ss.json"), defaultPaths("/etc/kat/anytls.json")
	if a.socket == b.socket || a.stats == b.stats {
		t.Fatal("instances share paths", a, b)
	}
	if os.Geteuid() == 0 && (a.socket != "/run/kat/ss.sock" || a.stats != "/var/lib/kat/ss.stats.json") {
		t.Fatal(a)
	}
}

func TestParseCLI(t *testing.T) {
	c, e := parseCLI([]string{"close", "12", "-c", "/etc/kat/ss.json"})
	if e != nil || c.config != "/etc/kat/ss.json" || len(c.rest) != 2 {
		t.Fatal(c, e)
	}
	if _, e := parseCLI([]string{"-c", "a", "--socket", "b"}); e == nil {
		t.Fatal("both accepted")
	}
	if _, e := parseCLI([]string{"--bogus"}); e == nil {
		t.Fatal("unknown flag accepted")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "x.json")
	os.WriteFile(cfg, []byte(`{"api":{"socket":"/custom/x.sock"},"inbounds":[]}`), 0o600)
	if p, e := resolveSocket(cli{config: cfg}); e != nil || p != "/custom/x.sock" {
		t.Fatal(p, e)
	}
	os.WriteFile(cfg, []byte(`{"api":{"enabled":false},"inbounds":[]}`), 0o600)
	if _, e := resolveSocket(cli{config: cfg}); e == nil {
		t.Fatal("disabled API resolved")
	}
}

func TestManagementCommands(t *testing.T) {
	dir, e := os.MkdirTemp("", "katcli")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "k.sock")
	run := func(details bool) (*kernel.Server, func()) {
		c := kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, API: &kernel.APIOptions{Socket: sock}, Stats: &kernel.StatsOptions{Connections: details}}
		s, e := kernel.Start(c)
		if e != nil {
			t.Fatal(e)
		}
		return s, func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s.Close(ctx)
		}
	}
	cmd := func(args ...string) (string, error) {
		var b bytes.Buffer
		e := manage(append(args, "--socket", sock), &b)
		return b.String(), e
	}
	_, stop := run(false)
	out, e := cmd("stats")
	if e != nil || !strings.Contains(out, "socks5/127.0.0.1:0") || !strings.Contains(out, "final->direct") {
		t.Fatal(out, e)
	}
	out, e = cmd("stats", "--json")
	var v kernel.StatsView
	if e != nil || json.Unmarshal([]byte(out), &v) != nil || v.Version == "" {
		t.Fatal(out, e)
	}
	if _, e = cmd("conns"); e == nil || !strings.Contains(e.Error(), "connection details are disabled") {
		t.Fatal("details hint missing", e)
	}
	if _, e = cmd("conns", "close", "--all"); e == nil || !strings.Contains(e.Error(), "disabled") {
		t.Fatal(e)
	}
	if out, e = cmd("log", "level", "warn"); e != nil || out != "log level set to warn\n" {
		t.Fatal(out, e)
	}
	if out, e = cmd("log", "level"); e != nil || out != "warn\n" {
		t.Fatal(out, e)
	}
	if _, e = cmd("log", "level", "loud"); e == nil {
		t.Fatal("bad level accepted")
	}
	if out, e = cmd("stats", "reset"); e != nil || !strings.HasPrefix(out, "statistics reset") {
		t.Fatal(out, e)
	}
	stop()
	_, stop = run(true)
	defer stop()
	if out, e = cmd("conns"); e != nil || out != "no active connections\n" {
		t.Fatal(out, e)
	}
	if _, e = cmd("conns", "close", "42"); e == nil || !strings.Contains(e.Error(), "no active connection") {
		t.Fatal(e)
	}
	if out, e = cmd("conns", "close", "--all"); e != nil || out != "closed 0 connection(s)\n" {
		t.Fatal(out, e)
	}
	if e = manage([]string{"stats", "--socket", filepath.Join(dir, "missing.sock")}, &bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "cannot reach") {
		t.Fatal(e)
	}
}
