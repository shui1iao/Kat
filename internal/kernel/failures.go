package kernel

import (
	"context"
	"errors"
	"fmt"
	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Fixed categories only: never index by input, identity, peer or target.
type failureKind uint8

const (
	failAccept failureKind = iota
	failConnections
	failHandshakes
	failTLS
	failHandshake
	failAnyAuth
	failAnyProtocol
	failAnyBudget
	failAnyIO
	failDNS
	failRoute
	failDial
	failDialBudget
	failUDPInvalid
	failUDPBudget
	failUDPQueue
	failUDPTargets
	failUDPIO
	failUDPSource
	failTCPIO
	failOutboundDial // proxy outbound/group dial or UDP session setup failed
	failOutboundUDP  // outbound (or its chain/group) cannot carry UDP
	failRuleData     // rule set / GeoIP file or download unavailable
	failureKinds
)

var failureLabels = [failureKinds]string{
	"stage=accept reason=listener_io", "stage=admission reason=connection_limit",
	"stage=admission reason=handshake_limit", "stage=tls reason=handshake_failed",
	"stage=handshake reason=authentication_or_format", "stage=anytls reason=authentication_failed",
	"stage=anytls reason=protocol_violation", "stage=anytls reason=session_or_stream_budget",
	"stage=anytls reason=session_io", "stage=resolve reason=dns_failed",
	"stage=route reason=rule_reject", "stage=dial reason=connect_failed",
	"stage=dial reason=budget_wait_timeout", "stage=udp reason=authentication_replay_or_format",
	"stage=udp reason=association_or_handshake_limit", "stage=udp reason=queue_limit",
	"stage=udp reason=target_limit", "stage=udp reason=socket_io",
	"stage=udp reason=unauthorized_source_or_expired", "stage=relay reason=stream_io",
	"stage=outbound reason=proxy_connect_failed", "stage=outbound reason=udp_unsupported",
	"stage=route reason=rule_data_unavailable",
}

type failureBucket struct {
	next       atomic.Int64
	suppressed atomic.Uint64
}
type failureLog struct {
	buckets [failureKinds]failureBucket
	write   func([]byte) error
	close   func()
	once    sync.Once
}

func newFailureLog() *failureLog {
	w, c := diagnosticStderr()
	return &failureLog{write: w, close: c}
}

// Each fixed category emits at most once per five seconds per server. Suppressed
// occurrences are reported on that category's next emission; no timer or worker.
func (l *failureLog) emit(k failureKind, protocol string, inbound int, now time.Time) {
	if l == nil || k >= failureKinds {
		return
	}
	b := &l.buckets[k]
	n := now.UnixNano()
	old := b.next.Load()
	if n < old || !b.next.CompareAndSwap(old, n+int64(5*time.Second)) {
		b.suppressed.Add(1)
		return
	}
	switch protocol {
	case "shadowsocks", "anytls", "socks5", "trojan", "udp", "outbound":
	default:
		protocol = "other"
	}
	if inbound < -1 || inbound > 63 {
		inbound = -1
	}
	suppressed := b.suppressed.Swap(0)
	line := fmt.Appendf(nil, "kat event=failure %s protocol=%s inbound=%d suppressed=%d\n", failureLabels[k], protocol, inbound, suppressed)
	if l.write != nil {
		if e := l.write(line); e != nil {
			b.suppressed.Add(suppressed + 1)
		}
	} // diagnostic sink failure must not change forwarding
}
func (l *failureLog) shutdown() {
	if l != nil {
		l.once.Do(func() {
			if l.close != nil {
				l.close()
			}
		})
	}
}
func (s *Server) failure(k failureKind, protocol string, inbound int) {
	if s.ctx != nil && s.ctx.Err() != nil {
		return
	}
	s.failures.emit(k, protocol, inbound, time.Now())
}
func quietFailure(e error) bool {
	var h *ss.HandshakeError
	if errors.As(e, &h) && h.EmptyEOF() {
		return true
	}
	return e == nil || errors.Is(e, io.EOF) || errors.Is(e, net.ErrClosed) || errors.Is(e, os.ErrClosed) || errors.Is(e, context.Canceled) || errors.Is(e, io.ErrClosedPipe) || errors.Is(e, syscall.ECONNRESET) || errors.Is(e, syscall.EPIPE)
}
func anyTLSFailure(e error) (failureKind, bool) {
	if quietFailure(e) || errors.Is(e, A.ErrStreamClosed) {
		return 0, false
	}
	switch {
	case errors.Is(e, A.ErrAuthentication):
		return failAnyAuth, true
	case errors.Is(e, A.ErrProtocol):
		return failAnyProtocol, true
	case errors.Is(e, A.ErrSessionLimit), errors.Is(e, A.ErrStreamLimit), errors.Is(e, A.ErrQueueLimit), errors.Is(e, A.ErrSlowConsumer):
		return failAnyBudget, true
	default:
		return failAnyIO, true
	}
}
func (s *Server) outboundFailure(e error) {
	if quietFailure(e) {
		return
	}
	if errors.Is(e, errRouteReject) {
		s.failure(failRoute, "outbound", -1)
		return
	}
	var dns *net.DNSError
	if errors.Is(e, errDNS) || errors.As(e, &dns) {
		s.failure(failDNS, "outbound", -1)
		return
	}
	s.failure(failDial, "outbound", -1)
}

func (s *Server) resolutionFailure(e error) {
	if quietFailure(e) {
		return
	}
	if errors.Is(e, errRouteReject) {
		s.failure(failRoute, "outbound", -1)
	} else {
		s.failure(failDNS, "outbound", -1)
	}
}

// WriteDiagnosticLine is used only for the CLI's finite startup/exit messages.
// Runtime failures use the fixed-category limiter above. No retries or workers.
func WriteDiagnosticLine(line string) {
	if len(line) > 512 {
		return
	}
	write, close := diagnosticStderr()
	defer close()
	_ = write([]byte(line))
}
