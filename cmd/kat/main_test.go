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
