package kernel

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// codecMaxSessions is the session limit the running AnyTLS codec enforces.
func codecMaxSessions(t *testing.T, in Inbound) int {
	t.Helper()
	if in.anytlsServer == nil {
		t.Fatal("AnyTLS codec not prepared")
	}
	return int(reflect.ValueOf(in.anytlsServer).Elem().FieldByName("cfg").FieldByName("MaxSessions").Int())
}

// checkAndRun loads body as `kat check` does, then starts it as `kat run` does
// (Load + Start), and returns max_sessions of every inbound after each step.
func checkAndRun(t *testing.T, body string) (checked, running []int, s *Server) {
	t.Helper()
	c, e := Load(writeConfig(t, body))
	if e != nil {
		t.Fatalf("check %s: %v", body, e)
	}
	for _, in := range c.Inbounds {
		checked = append(checked, in.AnyTLS.MaxSessions)
	}
	r, e := Load(writeConfig(t, body))
	if e != nil {
		t.Fatalf("run load %s: %v", body, e)
	}
	s, e = Start(r)
	if e != nil {
		t.Fatalf("run start %s: %v", body, e)
	}
	t.Cleanup(func() { s.Close(context.Background()) })
	for _, in := range s.cfg.Inbounds {
		if got := codecMaxSessions(t, in); got != in.AnyTLS.MaxSessions {
			t.Fatalf("%s: codec max_sessions %d, options %d", body, got, in.AnyTLS.MaxSessions)
		}
		running = append(running, in.AnyTLS.MaxSessions)
	}
	return checked, running, s
}

func TestAnyTLSMaxSessionsFollowsConnections(t *testing.T) {
	for _, tc := range []struct {
		limits, extra string
		want          int
	}{
		{``, ``, 4096}, // connections omitted: 4096
		{``, `,"max_sessions":0`, 4096},
		{`"limits":{"connections":0},`, ``, 4096},
		{`"limits":{"connections":1000},`, ``, 1000},
		{`"limits":{"connections":1000},`, `,"max_sessions":0`, 1000},
		{`"limits":{"connections":1},`, ``, 1},
		{`"limits":{"connections":65536},`, ``, 65536},
	} {
		body := `{` + tc.limits + `"inbounds":[` + anyTLSIdentitiesJSON(1, tc.extra) + `]}`
		checked, running, s := checkAndRun(t, body)
		if checked[0] != tc.want || running[0] != tc.want {
			t.Fatalf("%s: max_sessions check=%d run=%d, want %d", body, checked[0], running[0], tc.want)
		}
		if cap(s.connSlots) != tc.want || s.cfg.Limits.LogicalStreams != 8192 {
			t.Fatalf("%s: connections %d logical_streams %d", body, cap(s.connSlots), s.cfg.Limits.LogicalStreams)
		}
	}
}

func TestAnyTLSMaxSessionsExplicitKept(t *testing.T) {
	for _, limits := range []string{``, `"limits":{"connections":1000},`, `"limits":{"connections":7},`} {
		for _, v := range []string{"1", "32", "512", "1000", "4096", "5000", "65536"} {
			body := `{` + limits + `"inbounds":[` + anyTLSIdentitiesJSON(1, `,"max_sessions":`+v) + `]}`
			checked, running, _ := checkAndRun(t, body)
			if got := []string{strconv.Itoa(checked[0]), strconv.Itoa(running[0])}; got[0] != v || got[1] != v {
				t.Fatalf("%s: explicit max_sessions became check=%s run=%s", body, got[0], got[1])
			}
		}
		// The accepted range and the error are unchanged.
		for _, bad := range []string{"65537", "-1", "100000"} {
			body := `{` + limits + `"inbounds":[` + anyTLSIdentitiesJSON(1, `,"max_sessions":`+bad) + `]}`
			if _, e := Load(writeConfig(t, body)); e == nil || e.Error() != "invalid AnyTLS budget" {
				t.Fatalf("%s: out-of-range max_sessions: %v", body, e)
			}
		}
	}
}

func TestAnyTLSMaxSessionsSharedIdentity(t *testing.T) {
	same := func(extra string) string {
		return `{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"identity-0"` + extra + `}}`
	}
	// The same password on two listeners shares one identity and one codec;
	// conflicts compare the effective values, as before.
	for _, tc := range []struct {
		limits, a, b string
		want         int
	}{
		{``, ``, ``, 4096},
		{`"limits":{"connections":1000},`, ``, ``, 1000},
		{`"limits":{"connections":1000},`, ``, `,"max_sessions":1000`, 1000},
		{``, `,"max_sessions":4096`, ``, 4096},
		{``, `,"max_sessions":512`, `,"max_sessions":512`, 512},
	} {
		body := `{` + tc.limits + `"inbounds":[` + same(tc.a) + `,` + same(tc.b) + `]}`
		checked, running, s := checkAndRun(t, body)
		for i := range 2 {
			if checked[i] != tc.want || running[i] != tc.want {
				t.Fatalf("%s: inbound %d check=%d run=%d, want %d", body, i, checked[i], running[i], tc.want)
			}
		}
		if s.cfg.Inbounds[0].anytlsServer != s.cfg.Inbounds[1].anytlsServer {
			t.Fatalf("%s: shared identity got two codecs", body)
		}
		if s.cfg.Limits.LogicalStreams != 8192 {
			t.Fatalf("%s: shared identity logical_streams %d", body, s.cfg.Limits.LogicalStreams)
		}
	}
	for _, tc := range []struct{ limits, a, b string }{
		{``, ``, `,"max_sessions":512`},                                // omitted = 4096, not 512
		{`"limits":{"connections":1000},`, ``, `,"max_sessions":4096`}, // omitted = 1000
		{``, `,"max_sessions":100`, `,"max_sessions":200`},
	} {
		body := `{` + tc.limits + `"inbounds":[` + same(tc.a) + `,` + same(tc.b) + `]}`
		if _, e := Load(writeConfig(t, body)); e == nil || !strings.Contains(e.Error(), "same AnyTLS identity has conflicting limits") {
			t.Fatalf("%s: conflict not rejected: %v", body, e)
		}
	}
	// Distinct identities: each omitted max_sessions follows connections on its
	// own; logical_streams still only sums max_streams.
	body := `{"limits":{"connections":2000},"inbounds":[` + anyTLSIdentitiesJSON(3, ``) +
		`,{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"other","max_sessions":256}}]}`
	checked, running, s := checkAndRun(t, body)
	want := []int{2000, 2000, 2000, 256}
	for i := range want {
		if checked[i] != want[i] || running[i] != want[i] {
			t.Fatalf("identity %d: check=%d run=%d, want %d", i, checked[i], running[i], want[i])
		}
	}
	if s.cfg.Limits.LogicalStreams != 16384 {
		t.Fatalf("logical_streams %d, want 4 x 4096", s.cfg.Limits.LogicalStreams)
	}
}

// kat check and kat run agree, and re-validation derives the default again
// from the current connections while a written value stays as written.
func TestAnyTLSMaxSessionsCheckRunConsistent(t *testing.T) {
	for _, body := range []string{
		`{"inbounds":[` + anyTLSIdentitiesJSON(2, ``) + `]}`,
		`{"limits":{"connections":300},"inbounds":[` + anyTLSIdentitiesJSON(2, ``) + `]}`,
		`{"limits":{"connections":300},"inbounds":[` + anyTLSIdentitiesJSON(2, `,"max_sessions":9000`) + `]}`,
	} {
		checked, running, _ := checkAndRun(t, body)
		if !reflect.DeepEqual(checked, running) {
			t.Fatalf("%s: check %v != run %v", body, checked, running)
		}
	}
	c, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(1, ``)+`,{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"written","max_sessions":4096}}]}`))
	if e != nil || c.Inbounds[0].AnyTLS.MaxSessions != 4096 || c.Inbounds[1].AnyTLS.MaxSessions != 4096 {
		t.Fatalf("load: %v, max_sessions %d / %d, want 4096 / 4096", e, c.Inbounds[0].AnyTLS.MaxSessions, c.Inbounds[1].AnyTLS.MaxSessions)
	}
	if e := c.Validate(); e != nil || c.Inbounds[0].AnyTLS.MaxSessions != 4096 {
		t.Fatalf("re-validate: %v %d", e, c.Inbounds[0].AnyTLS.MaxSessions)
	}
	c.Limits.Connections = 1000
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if got := codecMaxSessions(t, s.cfg.Inbounds[0]); got != 1000 {
		t.Fatalf("omitted max_sessions after connections change = %d, want 1000", got)
	}
	if got := codecMaxSessions(t, s.cfg.Inbounds[1]); got != 4096 {
		t.Fatalf("written max_sessions changed to %d", got)
	}
}
