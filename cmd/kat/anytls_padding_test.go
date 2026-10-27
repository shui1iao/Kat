package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAnyTLSPadding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "padding.json")
	for _, tc := range []struct {
		name, scheme string
		ok           bool
	}{
		{"empty-default", "", true},
		{"custom", "stop=2\n0=30-30\n1=100-200", true},
		{"invalid", "stop=0", false},
		{"oversized", "stop=1\n0=" + strings.Repeat("0", 4086) + "-0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.scheme)
			body := `{"inbounds":[{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"p","padding_scheme":` + string(b) + `}}]}`
			if e := os.WriteFile(p, []byte(body), 0600); e != nil {
				t.Fatal(e)
			}
			if e := execute([]string{"check", p}); (e == nil) != tc.ok {
				t.Fatalf("kat check: %v", e)
			}
		})
	}
}
