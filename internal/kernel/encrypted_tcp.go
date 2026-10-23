package kernel

import (
	"errors"
	"github.com/shui1iao/Kat/internal/snell"
	"io"
	"net"
	"time"
)

// Payload I/O always uses the authenticated codec, deadlines and addresses use
// the transport. This wrapper can never satisfy the raw *net.TCPConn fast path.
type encryptedStream struct {
	net.Conn
	codec io.ReadWriteCloser
}

func (c *encryptedStream) Read(b []byte) (int, error)  { return c.codec.Read(b) }
func (c *encryptedStream) Write(b []byte) (int, error) { return c.codec.Write(b) }
func (c *encryptedStream) Close() error                { return c.codec.Close() }
func (c *encryptedStream) CloseWrite() error {
	if v, ok := c.codec.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return errors.New("encrypted stream has no half-close")
}
func (s *Server) acceptSS(raw net.Conn, in Inbound) (request, error) {
	// No prefix/bufio/ReadFull here: SIP022 owns its one initial raw Read.
	codec, e := in.ssRuntime.codec.Accept(raw)
	if e != nil {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = raw.Close()
		return request{}, e
	}
	a := codec.Target()
	return request{Command: 1, Mode: "shadowsocks", UserIndex: 0, Target: Address{a.Host, a.Port}, Stream: &encryptedStream{raw, codec}}, nil
}
func (s *Server) handleSnell(raw net.Conn, in Inbound, releaseHand func()) {
	session, e := in.snellServer.AcceptContext(s.ctx, raw)
	if e != nil {
		return
	}
	defer session.Close()
	first := true
	for {
		if !first {
			if !acquire(s.handSlots) {
				s.counters.Rejected.Add(1)
				return
			}
			s.counters.Handshakes.Add(1)
		}
		raw.SetDeadline(time.Now().Add(s.cfg.Limits.HandshakeTimeout.value()))
		q, e := session.Next()
		if first {
			releaseHand()
			first = false
		} else {
			<-s.handSlots
			s.counters.Handshakes.Add(-1)
		}
		if e != nil {
			return
		}
		raw.SetDeadline(time.Time{})
		if q.Command == snell.UDP {
			r := request{Command: 3, Mode: "snell", UserIndex: 0, UDPRead: func() (packet, error) { a, b, e := q.ReadDatagram(); return packet{Address{a.Host, a.Port}, b}, e }, UDPWrite: func(a Address, b []byte) error { return q.WriteDatagram(snell.Address{Host: a.Host, Port: a.Port}, b) }, Reply: func(net.Conn, net.Addr, bool) error {
				if e := q.Approve(); e != nil {
					return e
				}
				return q.SendSuccess()
			}}
			_ = s.serveUDP(raw, r)
			return
		}
		out, e := s.dial(s.ctx, Address{q.Target.Host, q.Target.Port})
		if e != nil {
			_ = q.Reject(1, "destination unavailable")
			return
		}
		if e = q.Approve(); e != nil {
			out.Close()
			return
		}
		// Snell has real logical CloseWrite. Normal join must not Request.Close():
		// that would kill the physical session and truncate the reverse direction.
		stream := &encryptedStream{raw, q}
		idle := s.cfg.Limits.TCPIdle.value()
		if idle == 0 {
			idle = 5 * time.Minute
		}
		e = s.relayIdle(s.ctx, stream, out, idle)
		out.Close()
		if e != nil {
			return
		}
		raw.SetDeadline(time.Now().Add(s.cfg.Limits.DrainTimeout.value()))
		if e = q.Finish(); e != nil {
			return
		}
		raw.SetDeadline(time.Time{})
	}
}
