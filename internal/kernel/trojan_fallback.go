package kernel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// ---- Trojan request parsing and fallback (0.7.0) ----
//
// The request is read incrementally: the first byte that cannot belong to a
// Trojan request (56 hex digits, CRLF, command, address, CRLF) ends the
// parse at once instead of waiting for 56 bytes. With "fallback" set on the
// inbound, every byte read so far and the rest of the connection are then
// relayed unchanged to the fallback address (typically a local web site);
// without it the connection is closed as before. Kat itself dials the
// fallback address, so a loopback address is allowed there.

// trojanReject is a request that is not a valid Trojan request. head holds
// every byte read from the client; auth is true when the request had the
// form of a Trojan password hash that matched no user.
type trojanReject struct {
	auth bool
	head []byte
	err  error
}

func (e *trojanReject) Error() string { return "trojan: " + e.err.Error() }
func (e *trojanReject) Unwrap() error { return e.err }

var errTrojanFormat = errors.New("not a Trojan request")

func (in *Inbound) validateFallback(i int) error {
	if in.Fallback == "" {
		return nil
	}
	if in.Protocol != "trojan" {
		return fmt.Errorf("inbound %d: fallback is only valid for Trojan inbounds", i)
	}
	ap, e := netip.ParseAddrPort(in.Fallback)
	if e != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
		return fmt.Errorf("inbound %d: fallback must be a literal IP and non-zero port, e.g. 127.0.0.1:8080", i)
	}
	return nil
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// recordingReader keeps a copy of every byte read.
type recordingReader struct {
	r   io.Reader
	buf []byte
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.buf = append(r.buf, p[:n]...)
	return n, e
}

func parseTrojan(c net.Conn, in Inbound) (request, error) {
	r := request{Mode: "trojan", UserIndex: -1, Datagrams: trojanDatagrams{}}
	var head [58]byte
	n := 0
	for n < len(head) {
		m, e := c.Read(head[n:])
		for i := n; i < n+m; i++ {
			ok := isHexDigit(head[i])
			if i == 56 {
				ok = head[i] == '\r'
			} else if i == 57 {
				ok = head[i] == '\n'
			}
			if !ok {
				return r, &trojanReject{head: append([]byte(nil), head[:n+m]...), err: errTrojanFormat}
			}
		}
		n += m
		if n < len(head) && e != nil {
			return r, e
		}
	}
	match := 0
	for i, u := range in.Users {
		sum := sha256.Sum224([]byte(u.Password))
		var encoded [56]byte
		hex.Encode(encoded[:], sum[:])
		m := subtle.ConstantTimeCompare(head[:56], encoded[:])
		match |= m
		if m == 1 {
			r.UserIndex = i
		}
	}
	if match == 0 {
		return r, &trojanReject{auth: true, head: append([]byte(nil), head[:]...), err: errors.New("authentication failed")}
	}
	rr := &recordingReader{r: c, buf: append([]byte(nil), head[:]...)}
	reject := func(e error) (request, error) {
		if errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) || isTimeout(e) {
			return r, e
		}
		return r, &trojanReject{head: rr.buf, err: e}
	}
	v, e := readN(rr, 1)
	if e != nil {
		return reject(e)
	}
	r.Command = v[0]
	if r.Command != 1 && r.Command != 3 {
		return reject(errors.New("unsupported Trojan command"))
	}
	r.Target, e = readAddress(rr, false)
	if e != nil {
		return reject(e)
	}
	if e = expectCRLF(rr); e != nil {
		return reject(e)
	}
	return r, nil
}

// trojanFallback relays a rejected connection to the inbound's fallback
// address, starting with the bytes already read. An unreachable fallback
// closes the TLS connection cleanly (close_notify, then FIN).
func (s *Server) trojanFallback(c net.Conn, head []byte, in *Inbound) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		s.failure(failDialBudget, in.Protocol, in.logIndex)
		c.Close()
		return
	}
	s.counters.Dials.Add(1)
	out, e := (&net.Dialer{}).DialContext(ctx, "tcp", in.Fallback)
	s.dialSlots.release()
	s.counters.Dials.Add(-1)
	if e != nil {
		s.failure(failFallback, in.Protocol, in.logIndex)
		c.Close() // TLS close_notify, then FIN
		return
	}
	defer out.Close()
	s.fallbacks.Add(1)
	c.SetDeadline(time.Time{})
	if len(head) > 0 {
		if e := writeAll(out, head); e != nil {
			return
		}
	}
	_ = s.relay(s.ctx, c, out)
}
