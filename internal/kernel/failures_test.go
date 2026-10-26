package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFailureCategoriesBoundedAndPrivate(t *testing.T) {
	var b bytes.Buffer
	l := &failureLog{write: func(p []byte) error { _, e := b.Write(p); return e }}
	now := time.Unix(200, 0)
	for k := failureKind(0); k < failureKinds; k++ {
		l.emit(k, "password=evil.example 203.0.113.42 payload", 999, now)
		for i := 0; i < 100; i++ {
			l.emit(k, "anytls", 0, now.Add(time.Second))
		}
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != int(failureKinds) {
		t.Fatal("rate cap", len(lines))
	}
	for _, line := range lines {
		if len(line) > 220 || !strings.Contains(line, "protocol=other inbound=-1 suppressed=0") {
			t.Fatal("unsafe shape", line)
		}
	}
	for _, secret := range []string{"password", "evil.example", "203.0.113.42", "payload"} {
		if strings.Contains(b.String(), secret) {
			t.Fatal("input leaked")
		}
	}
	b.Reset()
	l.emit(failTLS, "anytls", 3, now.Add(5*time.Second))
	if !strings.Contains(b.String(), "suppressed=100") {
		t.Fatal("missing suppressed count", b.String())
	}
}
func TestFailureClassifiersIgnoreInputsAndNormalEOF(t *testing.T) {
	var b bytes.Buffer
	s := &Server{core: &core{ctx: context.Background(), failures: &failureLog{write: func(p []byte) error { _, e := b.Write(p); return e }}}}
	for _, e := range []error{nil, io.EOF, net.ErrClosed, context.Canceled} {
		if !quietFailure(e) {
			t.Fatal("normal close classified as failure")
		}
		s.outboundFailure(e)
		if _, ok := anyTLSFailure(e); ok {
			t.Fatal("normal AnyTLS close logged")
		}
	}
	if b.Len() != 0 {
		t.Fatal("normal close not silent")
	}
	s.outboundFailure(&net.DNSError{Err: "secret-password", Name: "private-target.example"})
	s.outboundFailure(fmt.Errorf("%w: private-target.example", errRouteReject))
	s.outboundFailure(errors.New("203.0.113.7 secret-key payload"))
	for _, word := range []string{"dns_failed", "rule_reject", "connect_failed"} {
		if !strings.Contains(b.String(), word) {
			t.Fatal(word)
		}
	}
	for _, word := range []string{"secret", "private-target", "203.0.113.7", "payload"} {
		if strings.Contains(b.String(), word) {
			t.Fatal("leak", word)
		}
	}
	cases := []struct {
		e error
		k failureKind
	}{{A.ErrAuthentication, failAnyAuth}, {fmt.Errorf("%w: malicious", A.ErrProtocol), failAnyProtocol}, {A.ErrSessionLimit, failAnyBudget}, {A.ErrSlowConsumer, failAnyBudget}, {io.ErrUnexpectedEOF, failAnyIO}}
	for _, v := range cases {
		k, ok := anyTLSFailure(v.e)
		if !ok || k != v.k {
			t.Fatal("category", v.e)
		}
	}
}
func TestFailureConcurrentCapAndBrokenSink(t *testing.T) {
	var mu sync.Mutex
	n := 0
	l := &failureLog{write: func(p []byte) error { mu.Lock(); n++; mu.Unlock(); return errors.New("sink unavailable") }}
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.emit(failUDPInvalid, "shadowsocks", 0, now)
			}
		}()
	}
	wg.Wait()
	if n != 1 || l.buckets[failUDPInvalid].suppressed.Load() != 3200 {
		t.Fatal("unbounded or lost suppression", n, l.buckets[failUDPInvalid].suppressed.Load())
	}
}
