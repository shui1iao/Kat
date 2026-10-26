package kernel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	VX "github.com/shui1iao/Kat/internal/vlessx"
	VT "github.com/shui1iao/Kat/internal/vtransport"
	"io"
	"net"
	"time"
)

type boundedStream struct {
	net.Conn
	rw       io.ReadWriteCloser
	deadline interface {
		SetDeadline(time.Time) error
		SetReadDeadline(time.Time) error
		SetWriteDeadline(time.Time) error
	}
}

func (c *boundedStream) Read(p []byte) (int, error)         { return c.rw.Read(p) }
func (c *boundedStream) Write(p []byte) (int, error)        { return c.rw.Write(p) }
func (c *boundedStream) Close() error                       { return c.rw.Close() }
func (c *boundedStream) SetDeadline(t time.Time) error      { return c.deadline.SetDeadline(t) }
func (c *boundedStream) SetReadDeadline(t time.Time) error  { return c.deadline.SetReadDeadline(t) }
func (c *boundedStream) SetWriteDeadline(t time.Time) error { return c.deadline.SetWriteDeadline(t) }

type halfStream struct {
	*boundedStream
	half interface{ CloseWrite() error }
}

func (c *halfStream) CloseWrite() error { return c.half.CloseWrite() }
func (s *Server) handleVLESS(raw net.Conn, in Inbound, releaseHand func()) {
	if in.Transport != nil {
		var c net.Conn = raw
		if in.tlsConfig != nil {
			tc := tls.Server(raw, in.tlsConfig)
			if tc.HandshakeContext(s.ctx) != nil {
				return
			}
			c = tc
		}
		releaseHand()
		c.SetDeadline(time.Time{})
		server, e := VT.NewServer(in.Transport.config(s.cfg.Limits))
		if e != nil {
			return
		}
		_ = server.ServeConn(s.ctx, c, func(ctx context.Context, st *VT.Stream, meta VT.Metadata) error {
			if meta.EarlyDataBytes > 0 {
				s.httpEarly.Add(1)
			}
			if !s.logicalSlots.try() {
				return errors.New("logical quota")
			}
			s.logical.Add(1)
			defer func() { s.logicalSlots.release(); s.logical.Add(-1) }()
			if !s.handSlots.try() {
				return errors.New("handshake quota")
			}
			s.counters.Handshakes.Add(1)
			base := &boundedStream{Conn: c, rw: st, deadline: st}
			var stream net.Conn = base
			// Only HTTPUpgrade can actually half-close this transport.
			if in.Transport.Type == "httpupgrade" {
				stream = &halfStream{base, st}
			}
			return s.vlessRequest(ctx, stream, nil, in, func() { s.handSlots.release(); s.counters.Handshakes.Add(-1) }, in.Transport.Type != "httpupgrade")
		})
		return
	}
	c, tr, e := acceptVLESSRawTransport(s.ctx, raw, in)
	if e != nil {
		return
	}
	if tr != nil {
		defer tr.Close()
	}
	_ = s.vlessRequest(s.ctx, c, tr, in, releaseHand, false)
}

// This decision uses only trusted static listener configuration, NEVER the
// unauthenticated request flow/UUID. Any non-empty configured flow keeps gate.
func vlessTLSNeedsGate(users []User) bool {
	if len(users) == 0 {
		return true
	}
	for _, u := range users {
		if u.Flow != "" {
			return true
		}
	}
	return false
}

// Preserve the old public record-sizing policy, including configs returned by
// GetConfigForClient, while retaining all other TLS config/callback fields.
func ordinaryVLESSTLSConfig(cfg *tls.Config) *tls.Config {
	local := cfg.Clone()
	local.DynamicRecordSizingDisabled = true
	if callback := local.GetConfigForClient; callback != nil {
		local.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			next, e := callback(hello)
			if e != nil || next == nil {
				return next, e
			}
			return ordinaryVLESSTLSConfig(next), nil
		}
	}
	return local
}
func acceptVLESSRawTransport(ctx context.Context, raw net.Conn, in Inbound) (net.Conn, *VX.Transport, error) {
	if in.realityServer != nil {
		tr, e := in.realityServer.Accept(ctx, raw)
		return tr, tr, e
	}
	if in.tlsConfig == nil {
		return raw, nil, nil
	}
	if vlessTLSNeedsGate(in.Users) {
		tr, e := VX.AcceptTLS(ctx, raw, in.tlsConfig)
		return tr, tr, e
	}
	c := tls.Server(raw, ordinaryVLESSTLSConfig(in.tlsConfig))
	if e := c.HandshakeContext(ctx); e != nil {
		return nil, nil, e
	}
	return c, nil, nil
}

func (s *Server) vlessRequest(ctx context.Context, c net.Conn, tr *VX.Transport, in Inbound, release func(), fullClose bool) error {
	ctx = withInboundMeta(withInbound(withSource(ctx, c.RemoteAddr()), in.logIndex), &in, c.LocalAddr(), c.RemoteAddr()) // routing, statistics, guard
	released := false
	doneHand := func() {
		if !released {
			released = true
			release()
		}
	}
	defer doneHand()
	_ = c.SetReadDeadline(time.Now().Add(s.cfg.Limits.HandshakeTimeout.value()))
	timeout := time.AfterFunc(s.cfg.Limits.HandshakeTimeout.value(), func() { c.Close() })
	q, e := VX.ReadRequest(c, func(q VX.Request) bool {
		if len(q.Seed) != 0 {
			return false
		}
		matched := false
		for _, u := range in.Users {
			id, _ := parseUUID(u.UUID)
			if subtle.ConstantTimeCompare(id[:], q.UUID[:]) == 1 {
				// Vision-only credentials cannot silently serve empty-flow TCP. Empty-flow
				// cmd3 is allowed but the Mux parser subsequently enforces UDP-only framing.
				matched = q.Flow == u.Flow || (u.Flow == VX.VisionFlow && q.Flow == "" && q.Command == 3)
			}
		}
		return matched
	})
	timeout.Stop()
	if e != nil {
		return e
	}
	doneHand()
	_ = c.SetDeadline(time.Time{})
	var out net.Conn
	var first []byte
	if q.Command == 1 {
		target := Address{q.Target.Host, q.Target.Port}
		// Sniffing (0.7.0) reads the plain stream only: not Vision (its padding
		// is parsed later) and not XHTTP.
		if q.Flow != VX.VisionFlow && (in.Transport == nil || in.Transport.Type != "xhttp") {
			ctx, c, first, _, _ = s.sniffTCP(ctx, c, target, nil)
		}
		var f *flow
		f, ctx = s.newFlow(ctx, "tcp", target)
		out, e = s.dial(ctx, target)
		if e != nil {
			f.end(dialResult(e))
			return e
		}
		defer f.end("ok")
		defer out.Close()
		if e = forwardSniffed(ctx, out, first); e != nil {
			return e
		}
	}
	if e = VX.WriteResponse(c); e != nil {
		return e
	}
	var vv *VX.Vision
	if q.Flow == VX.VisionFlow {
		if tr == nil {
			return errors.New("Vision transport missing gate")
		}
		vv, e = VX.NewVision(tr, q.UUID)
		if e != nil {
			return e
		}
		c = &halfStream{&boundedStream{Conn: tr, rw: vv, deadline: tr}, vv}
		defer func() {
			r, w := vv.DirectState()
			if r {
				s.visionRead.Add(1)
			}
			if w {
				s.visionWrite.Add(1)
			}
		}()
	}
	switch q.Command {
	case 1:
		if in.Transport != nil && in.Transport.Type == "xhttp" {
			s.relayXHTTP(ctx, c, out)
			return nil
		}
		if fullClose {
			s.relayAnyTLS(ctx, c, out)
			return nil
		}
		return s.relay(ctx, c, out)
	case 2:
		return s.serveUDP(c, request{Context: ctx, Command: 3, Mode: "vless-stream", Target: Address{q.Target.Host, q.Target.Port}, Datagrams: vlessDatagrams{}})
	case 3:
		return s.serveMux(ctx, c, q.UUID)
	}
	return errors.New("unsupported VLESS command")
}
