package kernel

import (
	"context"
	"crypto/sha256"
	"errors"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync/atomic"
	"time"
)

type AnyTLSOptions struct {
	Password       string   `json:"password"`
	MaxSessions    int      `json:"max_sessions,omitempty"`
	MaxStreams     int      `json:"max_streams,omitempty"` // all sessions for this identity
	SessionStreams int      `json:"session_streams,omitempty"`
	StreamBytes    int      `json:"stream_bytes,omitempty"`
	SessionBytes   int      `json:"session_bytes,omitempty"`
	SlowTimeout    Duration `json:"slow_timeout,omitempty"`
}

// Third-party clients (Surge, mihomo, sing-box) open a new session whenever no
// idle one exists, so max_sessions is effectively the identity's concurrent
// connection count across all of its users. mihomo also gives every UDP flow a
// session of its own and keeps it for 60s after the flow's last packet. Every
// session is one physical connection, already bounded by limits.connections,
// so an omitted (or 0) max_sessions follows limits.connections (default 4096)
// instead of a fixed number; a written value is used as is (1..65536).
//
// slow_timeout bounds how long a session write may stay blocked on a peer that
// is not reading. Such clients multiplex many streams over one session, so a
// short pause in reading followed by many large downloads can keep a busy
// session blocked for longer than 10s; 60s (the maximum) avoids closing it.
const (
	defaultAnyTLSStreams        = 4096
	defaultAnyTLSSessionStreams = 64
	defaultAnyTLSSlowTimeout    = 60 * time.Second
)

// connections is the validated limits.connections, the max_sessions default.
func (o *AnyTLSOptions) normalize(connections int) error {
	if o == nil || len(o.Password) == 0 || len(o.Password) > 4096 {
		return errors.New("AnyTLS requires single password")
	}
	defs := []struct {
		p      *int
		v, max int
	}{{&o.MaxSessions, connections, 65536}, {&o.MaxStreams, defaultAnyTLSStreams, 65536}, {&o.SessionStreams, defaultAnyTLSSessionStreams, 64}, {&o.StreamBytes, 131072, 4 << 20}, {&o.SessionBytes, 1048576, 16 << 20}}
	for _, d := range defs {
		if *d.p == 0 {
			*d.p = d.v
		}
		if *d.p < 1 || *d.p > d.max {
			return errors.New("invalid AnyTLS budget")
		}
	}
	if o.StreamBytes < 65542 || o.SessionBytes < o.StreamBytes {
		return errors.New("AnyTLS byte budgets must fit full frame")
	}
	if o.SlowTimeout == 0 {
		o.SlowTimeout = Duration(defaultAnyTLSSlowTimeout)
	}
	if o.SlowTimeout.value() < time.Millisecond || o.SlowTimeout.value() > time.Minute {
		return errors.New("invalid AnyTLS slow timeout")
	}
	return nil
}

// prepareAnyTLS creates the AnyTLS codecs; a previous codec with an
// identical configuration is reused (budgets continue across a reload).
func (s *Server) prepareAnyTLS(prev *Server) error {
	codecs := map[[32]byte]*A.Server{}
	options := map[[32]byte]AnyTLSOptions{}
	type anyPrev struct {
		conf  A.Config
		codec *A.Server
	}
	var prevs []anyPrev
	if prev != nil {
		for _, in := range prev.cfg.Inbounds {
			if in.anytlsServer != nil {
				prevs = append(prevs, anyPrev{in.anytlsConf, in.anytlsServer})
			}
		}
	}
	for i := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[i]
		if in.AnyTLS == nil {
			continue
		}
		o := in.AnyTLS
		id := sha256.Sum256([]byte(o.Password))
		if old, ok := options[id]; ok && old != *o {
			return errors.New("same AnyTLS identity must share budgets")
		}
		codec := codecs[id]
		conf := A.Config{Password: o.Password, MaxSessions: o.MaxSessions, MaxTotalStreams: o.MaxStreams, MaxStreams: o.SessionStreams, StreamInboundBytes: o.StreamBytes, StreamOutboundBytes: o.StreamBytes, SessionInboundBytes: o.SessionBytes, SessionOutboundBytes: o.SessionBytes, HandshakeTimeout: s.cfg.Limits.HandshakeTimeout.value(), TargetTimeout: s.cfg.Limits.HandshakeTimeout.value(), SlowConsumerTimeout: o.SlowTimeout.value(), WriteTimeout: o.SlowTimeout.value()}
		if codec == nil {
			for _, p := range prevs {
				if reflect.DeepEqual(p.conf, conf) {
					codec = p.codec
					break
				}
			}
		}
		if codec == nil {
			var e error
			codec, e = A.NewServer(conf)
			if e != nil {
				return errors.New("invalid AnyTLS server config")
			}
		}
		codecs[id] = codec
		options[id] = *o
		in.anytlsServer = codec
		in.anytlsConf = conf
	}
	return nil
}

// Per-stream deadlines must never be forwarded to the TLS physical connection.
type anyStream struct {
	net.Conn
	st *A.Stream
}

func (c *anyStream) Read(p []byte) (int, error)         { return c.st.Read(p) }
func (c *anyStream) Write(p []byte) (int, error)        { return c.st.Write(p) }
func (c *anyStream) Close() error                       { return c.st.Close() }
func (c *anyStream) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *anyStream) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *anyStream) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }

// FIN is whole-stream close. Do not offer a fabricated half-close capability.
func (s *Server) serveAnyTLS(parent context.Context, c net.Conn, in Inbound) {
	acc := s
	e := in.anytlsServer.Serve(parent, c, func(ctx context.Context, st *A.Stream, r A.Request) {
		// Each stream is a new proxied connection: it is routed by the current
		// configuration even when its session was accepted by an older one.
		// The current generation cannot be released while it is current, so
		// the loop ends as soon as a reload in progress has been installed.
		s := acc.current()
		for s.core != nil && !s.tryRef() {
			runtime.Gosched()
			s = acc.current()
		}
		if s != acc {
			ctx = acc.withInboundStat(ctx)
			ctx = s.currentInboundMeta(ctx, acc)
		}
		defer s.unref()
		if !s.logicalSlots.try() {
			s.failure(failAnyBudget, in.Protocol, in.logIndex)
			s.counters.Rejected.Add(1)
			st.Close()
			return
		}
		s.logical.Add(1)
		defer func() { s.logicalSlots.release(); s.logical.Add(-1); st.Close() }()
		if ctx.Err() != nil {
			return
		}
		stream := &anyStream{c, st}
		if r.UDP != nil {
			udp := r.UDP
			q := request{Context: ctx, Command: 3, Mode: "anytls", UDPRead: func() (packet, error) {
				a, b, e := udp.ReadPacket()
				if len(b) > maxDatagram && e == nil {
					e = errors.New("AnyTLS UDP exceeds native UDP maximum")
				}
				return packet{Address{a.Host, a.Port}, b}, e
			}, UDPWrite: func(a Address, b []byte) error {
				from := A.Address{Host: a.Host, Port: a.Port}
				if udp.Connected() {
					from = udp.Target()
				}
				return udp.WritePacket(from, b)
			}}
			if e := s.serveUDP(stream, q); !quietFailure(e) {
				s.failure(failUDPIO, in.Protocol, in.logIndex)
			}
			return
		}
		target := Address{r.Target.Host, r.Target.Port}
		sctx, sstream, first, _, _ := s.sniffTCP(ctx, stream, target, nil)
		f, fctx := s.newFlow(sctx, "tcp", target)
		out, e := s.dial(fctx, target)
		if e != nil {
			f.end(dialResult(e))
			return
		}
		defer f.end("ok")
		defer out.Close()
		if forwardSniffed(fctx, out, first) != nil {
			return
		}
		s.relayAnyTLS(fctx, sstream, out)
	})
	if k, ok := anyTLSFailure(e); ok {
		s.failure(k, in.Protocol, in.logIndex)
	}
	if errors.Is(e, A.ErrAuthentication) {
		s.authFailed(c.RemoteAddr(), &in)
	}
}

// Session FIN cancels its stream, so stop both directions on EOF rather than
// falsely asserting TCP half-close. Join both workers before returning to Serve.
func (s *Server) relayAnyTLS(ctx context.Context, stream, out net.Conn) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan error, 2)
	a := &activityStream{stream, &last}
	b := &activityStream{out, &last}
	mUp, mDown := meters(ctx)
	go func() { done <- s.copyAnyTLSDownM(a, b, out, mDown) }()
	go func() { done <- s.copyAnyTLSUpM(b, a, mUp) }()
	idle := s.cfg.Limits.TCPIdle.value()
	if idle == 0 {
		idle = 5 * time.Minute
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			stream.Close()
			out.Close()
			<-done
			<-done
			return
		case e := <-done:
			if !quietFailure(e) && !errors.Is(e, A.ErrStreamClosed) {
				s.failure(failTCPIO, "anytls", -1)
			}
			stream.Close()
			out.Close()
			<-done
			return
		case <-timer.C:
			remaining := idle - time.Since(time.Unix(0, last.Load()))
			if remaining <= 0 {
				stream.Close()
				out.Close()
				<-done
				<-done
				return
			}
			timer.Reset(remaining)
		}
	}
}

var _ io.ReadWriteCloser = (*anyStream)(nil)
