package kernel

import (
	"context"
	"crypto/sha256"
	"errors"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
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

func (o *AnyTLSOptions) normalize() error {
	if o == nil || len(o.Password) == 0 || len(o.Password) > 4096 {
		return errors.New("AnyTLS requires single password")
	}
	defs := []struct {
		p      *int
		v, max int
	}{{&o.MaxSessions, 32, 65536}, {&o.MaxStreams, 64, 65536}, {&o.SessionStreams, 16, 64}, {&o.StreamBytes, 131072, 4 << 20}, {&o.SessionBytes, 1048576, 16 << 20}}
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
		o.SlowTimeout = Duration(10 * time.Second)
	}
	if o.SlowTimeout.value() < time.Millisecond || o.SlowTimeout.value() > time.Minute {
		return errors.New("invalid AnyTLS slow timeout")
	}
	return nil
}
func (s *Server) prepareAnyTLS() error {
	codecs := map[[32]byte]*A.Server{}
	options := map[[32]byte]AnyTLSOptions{}
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
		if codec == nil {
			var e error
			codec, e = A.NewServer(A.Config{Password: o.Password, MaxSessions: o.MaxSessions, MaxTotalStreams: o.MaxStreams, MaxStreams: o.SessionStreams, StreamInboundBytes: o.StreamBytes, StreamOutboundBytes: o.StreamBytes, SessionInboundBytes: o.SessionBytes, SessionOutboundBytes: o.SessionBytes, HandshakeTimeout: s.cfg.Limits.HandshakeTimeout.value(), TargetTimeout: s.cfg.Limits.HandshakeTimeout.value(), SlowConsumerTimeout: o.SlowTimeout.value(), WriteTimeout: o.SlowTimeout.value()})
			if e != nil {
				return errors.New("invalid AnyTLS server config")
			}
			codecs[id] = codec
			options[id] = *o
		}
		in.anytlsServer = codec
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
func (s *Server) serveAnyTLS(c net.Conn, in Inbound) {
	_ = in.anytlsServer.Serve(s.ctx, c, func(ctx context.Context, st *A.Stream, r A.Request) {
		if !acquire(s.logicalSlots) {
			s.counters.Rejected.Add(1)
			st.Close()
			return
		}
		s.logical.Add(1)
		defer func() { <-s.logicalSlots; s.logical.Add(-1); st.Close() }()
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
			_ = s.serveUDP(stream, q)
			return
		}
		out, e := s.dial(ctx, Address{r.Target.Host, r.Target.Port})
		if e != nil {
			return
		}
		defer out.Close()
		s.relayAnyTLS(ctx, stream, out)
	})
}

// Session FIN cancels its stream, so stop both directions on EOF rather than
// falsely asserting TCP half-close. Join both workers before returning to Serve.
func (s *Server) relayAnyTLS(ctx context.Context, stream, out net.Conn) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan error, 2)
	a := &activityStream{stream, &last}
	b := &activityStream{out, &last}
	go func() { done <- s.copyAnyTLSDown(a, b, out) }()
	go func() { done <- s.copyAnyTLSUp(b, a) }()
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
		case <-done:
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
