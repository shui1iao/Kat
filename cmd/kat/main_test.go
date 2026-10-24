package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommands(t *testing.T) {
	if e := execute([]string{"version"}); e != nil {
		t.Fatal(e)
	}
	for _, a := range [][]string{nil, {"unknown"}, {"run"}, {"check", "/nonexistent"}} {
		if execute(a) == nil {
			t.Fatal("invalid invocation accepted")
		}
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if e := os.WriteFile(p, []byte(`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := execute([]string{"check", p}); e != nil {
		t.Fatal(e)
	}
}

func TestCheckAnyTLSWithoutTLS(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		tls string
		ok  bool
	}{{"", true}, {`,"tls":null`, false}, {`,"tls":{}`, false}, {`,"tls":{"cert":"c.pem"}`, false}, {`,"tls":{"key":"k.pem"}`, false}} {
		p := filepath.Join(dir, "anytls.json")
		body := `{"inbounds":[{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"p"}` + c.tls + `}]}`
		if e := os.WriteFile(p, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if e := execute([]string{"check", p}); (e == nil) != c.ok {
			t.Fatalf("check %s: %v", body, e)
		}
	}
	p := filepath.Join(dir, "trojan.json")
	os.WriteFile(p, []byte(`{"inbounds":[{"protocol":"trojan","listen":"127.0.0.1:0","users":[{"password":"p"}]}]}`), 0600)
	if execute([]string{"check", p}) == nil {
		t.Fatal("trojan without tls accepted")
	}
}
