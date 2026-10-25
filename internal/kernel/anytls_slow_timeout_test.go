package kernel

import (
	"context"
	"testing"
	"time"
)

func TestAnyTLSSlowTimeoutDefault(t *testing.T) {
	// Omitted (and 0, which JSON omitempty cannot distinguish) means the default.
	for _, extra := range []string{``, `,"slow_timeout":"0s"`} {
		c, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(1, extra)+`]}`))
		if e != nil {
			t.Fatal(extra, e)
		}
		if got := c.Inbounds[0].AnyTLS.SlowTimeout.value(); got != 60*time.Second {
			t.Fatalf("slow_timeout %q default = %v, want 60s", extra, got)
		}
	}
}

func TestAnyTLSSlowTimeoutExplicitKept(t *testing.T) {
	for _, tc := range []struct {
		text string
		want time.Duration
	}{{"1ms", time.Millisecond}, {"500ms", 500 * time.Millisecond}, {"10s", 10 * time.Second}, {"30s", 30 * time.Second}, {"60s", time.Minute}, {"1m", time.Minute}} {
		body := `{"inbounds":[` + anyTLSIdentitiesJSON(1, `,"slow_timeout":"`+tc.text+`"`) + `]}`
		c, e := Load(writeConfig(t, body))
		if e != nil {
			t.Fatal(tc.text, e)
		}
		if got := c.Inbounds[0].AnyTLS.SlowTimeout.value(); got != tc.want {
			t.Fatalf("explicit slow_timeout %s became %v", tc.text, got)
		}
		// Start re-validates and builds the AnyTLS codec from this value.
		s, e := Start(c)
		if e != nil {
			t.Fatal(tc.text, e)
		}
		got := s.cfg.Inbounds[0].AnyTLS.SlowTimeout.value()
		s.Close(context.Background())
		if got != tc.want {
			t.Fatalf("explicit slow_timeout %s after Start = %v", tc.text, got)
		}
	}
	// The accepted range is unchanged: 1ms to 1 minute.
	for _, bad := range []string{"999us", "61s", "2m"} {
		if _, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(1, `,"slow_timeout":"`+bad+`"`)+`]}`)); e == nil {
			t.Fatalf("out-of-range slow_timeout %s accepted", bad)
		}
	}
	for _, bad := range []AnyTLSOptions{{Password: "p", SlowTimeout: Duration(time.Minute + time.Nanosecond)}, {Password: "p", SlowTimeout: Duration(-time.Second)}} {
		if e := bad.normalize(defaultConnections); e == nil {
			t.Fatalf("out-of-range slow_timeout accepted: %v", bad.SlowTimeout.value())
		}
	}
}
