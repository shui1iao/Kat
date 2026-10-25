package kernel

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// anyTLSIdentitiesJSON returns n AnyTLS inbounds with distinct passwords and
// the given extra "anytls" members (e.g. `,"max_streams":64`).
func anyTLSIdentitiesJSON(n int, extra string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"identity-%d"%s}}`, i, extra)
	}
	return strings.Join(parts, ",")
}

func TestDefaultLimitsValues(t *testing.T) {
	c, e := Load(writeConfig(t, `{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	l := c.Limits
	for _, v := range []struct {
		name      string
		got, want int
	}{
		{"connections", l.Connections, 4096},
		{"logical_streams", l.LogicalStreams, 8192},
		{"handshakes", l.Handshakes, 512},
		{"dials", l.Dials, 512},
		{"udp_associations", l.UDPAssociations, 1024},
		{"udp_targets", l.UDPTargets, 256},
		// Unchanged defaults.
		{"udp_queue", l.UDPQueue, 16},
		{"udp_queue_bytes", l.UDPQueueBytes, 16 * maxDatagram},
		{"buffer_size", l.BufferSize, 16384},
		{"pool_buffers", l.PoolBuffers, 128},
	} {
		if v.got != v.want {
			t.Errorf("%s default = %d, want %d", v.name, v.got, v.want)
		}
	}
}

func TestDefaultAnyTLSBudgets(t *testing.T) {
	o := &AnyTLSOptions{Password: "p"}
	if e := o.normalize(defaultConnections); e != nil {
		t.Fatal(e)
	}
	// max_sessions follows limits.connections (default 4096); see anytls_max_sessions_test.go.
	if o.MaxSessions != 4096 || o.MaxStreams != 4096 || o.SessionStreams != 64 || o.StreamBytes != 131072 || o.SessionBytes != 1048576 || o.SlowTimeout.value().String() != "1m0s" {
		t.Fatalf("AnyTLS defaults %+v", *o)
	}
	// Hard ranges are unchanged: session_streams <= 64, counts <= 65536.
	for _, bad := range []AnyTLSOptions{{Password: "p", SessionStreams: 65}, {Password: "p", MaxSessions: 65537}, {Password: "p", MaxStreams: 65537}, {Password: "p", MaxSessions: -1}} {
		if e := bad.normalize(defaultConnections); e == nil {
			t.Fatalf("out-of-range AnyTLS budget accepted: %+v", bad)
		}
	}
}

func TestExplicitLimitsKeepWrittenValues(t *testing.T) {
	// Values a deployment might write explicitly as a 0.6.1 workaround, plus deliberately small ones.
	for _, tc := range []struct {
		limits, anytls string
		want           Limits
		wantAny        AnyTLSOptions
	}{
		{`"connections":4096,"logical_streams":4096`, `,"max_sessions":512,"max_streams":4096,"session_streams":64`,
			Limits{Connections: 4096, LogicalStreams: 4096, Handshakes: 512, Dials: 512, UDPAssociations: 1024, UDPTargets: 256}, AnyTLSOptions{MaxSessions: 512, MaxStreams: 4096, SessionStreams: 64}},
		{`"connections":1024,"logical_streams":256,"handshakes":64,"dials":64,"udp_associations":128,"udp_targets":64`, `,"max_sessions":32,"max_streams":64,"session_streams":16`,
			Limits{Connections: 1024, LogicalStreams: 256, Handshakes: 64, Dials: 64, UDPAssociations: 128, UDPTargets: 64}, AnyTLSOptions{MaxSessions: 32, MaxStreams: 64, SessionStreams: 16}},
		{`"connections":7,"logical_streams":5,"handshakes":3,"dials":2,"udp_associations":1,"udp_targets":1`, `,"max_sessions":1,"max_streams":5,"session_streams":1`,
			Limits{Connections: 7, LogicalStreams: 5, Handshakes: 3, Dials: 2, UDPAssociations: 1, UDPTargets: 1}, AnyTLSOptions{MaxSessions: 1, MaxStreams: 5, SessionStreams: 1}},
	} {
		body := `{"limits":{` + tc.limits + `},"inbounds":[` + anyTLSIdentitiesJSON(1, tc.anytls) + `]}`
		c, e := Load(writeConfig(t, body))
		if e != nil {
			t.Fatal(body, e)
		}
		l := c.Limits
		if l.Connections != tc.want.Connections || l.LogicalStreams != tc.want.LogicalStreams || l.Handshakes != tc.want.Handshakes || l.Dials != tc.want.Dials || l.UDPAssociations != tc.want.UDPAssociations || l.UDPTargets != tc.want.UDPTargets {
			t.Fatalf("%s: limits %+v", body, l)
		}
		o := c.Inbounds[0].AnyTLS
		if o.MaxSessions != tc.wantAny.MaxSessions || o.MaxStreams != tc.wantAny.MaxStreams || o.SessionStreams != tc.wantAny.SessionStreams {
			t.Fatalf("%s: anytls %+v", body, *o)
		}
		// Start re-validates; explicit values must survive unchanged.
		s, e := Start(c)
		if e != nil {
			t.Fatal(e)
		}
		if cap(s.logicalSlots) != tc.want.LogicalStreams || cap(s.connSlots) != tc.want.Connections || cap(s.handSlots) != tc.want.Handshakes || cap(s.dialSlots) != tc.want.Dials || cap(s.udpSlots) != tc.want.UDPAssociations {
			t.Fatalf("%s: runtime slots differ from explicit limits", body)
		}
		s.Close(context.Background())
	}
}

func TestLogicalStreamsAutoCoversAnyTLSIdentities(t *testing.T) {
	for _, tc := range []struct {
		identities int
		extra      string
		want       int
	}{
		{1, "", 8192},
		{2, "", 8192},  // 2 x 4096 = 8192
		{3, "", 12288}, // previously rejected: 3 x 64 <= 256 was fine, but 3 x 4096 > 8192
		{16, "", 65536},
		{5, `,"max_streams":64`, 8192},
		{2, `,"max_streams":10000`, 20000},
	} {
		body := `{"inbounds":[` + anyTLSIdentitiesJSON(tc.identities, tc.extra) + `]}`
		c, e := Load(writeConfig(t, body))
		if e != nil {
			t.Fatalf("%d identities%s rejected: %v", tc.identities, tc.extra, e)
		}
		if c.Limits.LogicalStreams != tc.want {
			t.Fatalf("%d identities%s: logical_streams %d, want %d", tc.identities, tc.extra, c.Limits.LogicalStreams, tc.want)
		}
		// Re-validation (as Start does) keeps the derived value and still treats it as automatic.
		if e := c.Validate(); e != nil || c.Limits.LogicalStreams != tc.want {
			t.Fatalf("re-validate: %v %d", e, c.Limits.LogicalStreams)
		}
	}
	// Mixed: one default identity plus the same identity on a second listener counts once.
	body := `{"inbounds":[` + anyTLSIdentitiesJSON(3, "") + `,{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"identity-0"}}]}`
	c, e := Load(writeConfig(t, body))
	if e != nil || c.Limits.LogicalStreams != 12288 {
		t.Fatalf("shared identity counted twice: %v %d", e, c.Limits.LogicalStreams)
	}
	// Start uses the derived value for the global logical slot budget.
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if cap(s.logicalSlots) != 12288 {
		t.Fatalf("runtime logical slots %d", cap(s.logicalSlots))
	}
}

func TestLogicalStreamsAutoRecomputedAfterIdentityChange(t *testing.T) {
	c, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(1, "")+`]}`))
	if e != nil || c.Limits.LogicalStreams != 8192 {
		t.Fatal(e, c.Limits.LogicalStreams)
	}
	more, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(3, "")+`]}`))
	if e != nil {
		t.Fatal(e)
	}
	c.Inbounds = more.Inbounds
	if e := c.Validate(); e != nil || c.Limits.LogicalStreams != 12288 {
		t.Fatalf("auto value not recomputed: %v %d", e, c.Limits.LogicalStreams)
	}
	// A value written after validation is explicit again and keeps the original constraint.
	c.Limits.LogicalStreams = 8192
	if e := c.Validate(); e == nil || !strings.Contains(e.Error(), "exceed logical_streams") {
		t.Fatalf("explicit logical_streams not enforced: %v", e)
	}
}

func TestLogicalStreamsExplicitKeepsConstraint(t *testing.T) {
	for _, tc := range []struct {
		limits, extra string
		identities    int
		ok            bool
	}{
		{`"logical_streams":256`, "", 1, false},                    // 4096 > 256
		{`"logical_streams":8192`, "", 3, false},                   // 12288 > 8192, never raised when written
		{`"logical_streams":12288`, "", 3, true},                   // exactly the sum
		{`"logical_streams":256`, `,"max_streams":64`, 4, true},    // 0.6.1 boundary: 256 <= 256
		{`"logical_streams":256`, `,"max_streams":64`, 5, false},   // 0.6.1 boundary: 320 > 256
		{`"logical_streams":4096`, `,"max_streams":4096`, 1, true}, // explicit 0.6.1 workaround
		{`"logical_streams":65537`, `,"max_streams":64`, 1, false}, // range unchanged
	} {
		body := `{"limits":{` + tc.limits + `},"inbounds":[` + anyTLSIdentitiesJSON(tc.identities, tc.extra) + `]}`
		c, e := Load(writeConfig(t, body))
		if (e == nil) != tc.ok {
			t.Fatalf("%s: %v", body, e)
		}
		if e == nil && fmt.Sprintf(`"logical_streams":%d`, c.Limits.LogicalStreams) != tc.limits {
			t.Fatalf("%s: explicit logical_streams changed to %d", body, c.Limits.LogicalStreams)
		}
		if e != nil && !tc.ok && !strings.Contains(e.Error(), "logical_streams") && !strings.Contains(e.Error(), "resource count") {
			t.Fatalf("%s: unexpected error %v", body, e)
		}
	}
}

func TestLogicalStreamsAutoStillBounded(t *testing.T) {
	// 17 default identities need 69632 workers: more than the 65536 hard maximum.
	_, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(17, "")+`]}`))
	if e == nil || !strings.Contains(e.Error(), "65536 logical_streams maximum") {
		t.Fatalf("unbounded automatic logical_streams: %v", e)
	}
	// Explicit per-identity quotas make the same 17 identities valid again.
	c, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(17, `,"max_streams":1024`)+`]}`))
	if e != nil || c.Limits.LogicalStreams != 17408 {
		t.Fatalf("explicit identity quotas: %v %d", e, c.Limits.LogicalStreams)
	}
}
