package anytls

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestMetadataLiteralSettingsCompatibility(t *testing.T) {
	raw, e := os.ReadFile("testdata/metadata-settings.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures []struct {
		Name, Hex string
		Valid     bool
	}
	if e = json.Unmarshal(raw, &fixtures); e != nil {
		t.Fatal(e)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			data, e := hex.DecodeString(f.Hex)
			if e != nil {
				t.Fatal(e)
			}
			version, _, e := parseSettings(data)
			if (e == nil) != f.Valid {
				t.Fatalf("literal parser valid=%v got=%v", f.Valid, e)
			}
			if !f.Valid {
				if !errors.Is(e, ErrProtocol) {
					t.Fatal(e)
				}
				return
			}
			if version != 1 && version != 2 {
				t.Fatal(version)
			}
			called := make(chan Request, 1)
			c := start(t, cfg(), func(ctx context.Context, st *Stream, r Request) { called <- r; st.Write([]byte("ok")) })
			c.send(t, fixturesAuth(t))
			c.send(t, wire(cmdSettings, 0, data))
			if version == 2 {
				c.next(t, cmdServerSettings, 0)
			}
			c.send(t, wire(cmdSYN, 1, nil))
			if version == 2 {
				c.next(t, cmdSYNACK, 1)
			}
			c.send(t, wire(cmdPSH, 1, targetBytes(t, Address{"127.0.0.1", 443})))
			request := <-called
			if request.UserID != "fixture-user" {
				t.Fatal("software metadata changed authenticated identity", request)
			}
			reply := c.next(t, cmdPSH, 1)
			if string(reply.data) != "ok" {
				t.Fatal(reply)
			}
		})
	}
}
func fixturesAuth(t *testing.T) []byte { return fixtures(t)["auth"] }
func TestMetadataOversizedWireSettingsStillRejected(t *testing.T) {
	c := start(t, cfg(), func(context.Context, *Stream, Request) { t.Error("oversized settings callback") })
	c.send(t, fixturesAuth(t))
	data := make([]byte, 4097)
	_ = c.write(wire(cmdSettings, 0, data))
	c.next(t, cmdAlert, 0)
	e := <-c.result
	c.result <- e
	if !errors.Is(e, ErrProtocol) {
		t.Fatal(e)
	}
}
