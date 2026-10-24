// Package socks5 is a SOCKS5 client outbound (RFC 1928, RFC 1929): CONNECT
// and UDP ASSOCIATE, no-auth or username/password. Every connection to the
// proxy server goes through the "under" dialer.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

const typeName = "socks5"

var errOptions = errors.New("socks5: invalid outbound options")

// Validate checks o statically (no I/O).
func Validate(o outbound.Options) error {
	if o.Type != typeName {
		return fmt.Errorf("%w: type must be %q", errOptions, typeName)
	}
	if o.Name == "" {
		return fmt.Errorf("%w: name required", errOptions)
	}
	if !validServer(o.Server) {
		return fmt.Errorf("%w: server must be an IP literal or a valid domain name", errOptions)
	}
	if o.Port == 0 {
		return fmt.Errorf("%w: port must be 1..65535", errOptions)
	}
	if o.Method != "" || o.Key != "" || o.TLS != nil || o.IdleSessions != 0 || o.IdleTimeout != 0 {
		return fmt.Errorf("%w: only server, port, username, password, udp, via apply to socks5", errOptions)
	}
	if (o.Username == "") != (o.Password == "") {
		return fmt.Errorf("%w: username and password must be set together", errOptions)
	}
	if len(o.Username) > 255 || len(o.Password) > 255 {
		return fmt.Errorf("%w: username/password must be 1..255 bytes", errOptions)
	}
	return nil
}

// validServer accepts an IP literal without zone or an LDH domain name.
func validServer(s string) bool {
	if s == "" {
		return false
	}
	if ip, e := netip.ParseAddr(s); e == nil {
		return ip.Zone() == ""
	}
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Outbound is a SOCKS5 client.
type Outbound struct {
	name, user, pass string
	server           outbound.Addr
	udp              bool
	under            outbound.Dialer
}

var _ outbound.Outbound = (*Outbound)(nil)

// New builds the outbound. It performs no network I/O.
func New(o outbound.Options, under outbound.Dialer) (outbound.Outbound, error) {
	if e := Validate(o); e != nil {
		return nil, e
	}
	if under == nil {
		return nil, fmt.Errorf("%w: nil under dialer", errOptions)
	}
	return &Outbound{name: o.Name, user: o.Username, pass: o.Password, server: o.ServerAddr(), udp: o.UDPEnabled(), under: under}, nil
}

func (s *Outbound) Name() string { return s.name }
func (s *Outbound) Type() string { return typeName }
func (s *Outbound) Close() error { return nil }
func (s *Outbound) UDP() bool    { return s.udp && s.under.UDP() }

var (
	errAuthRejected = errors.New("socks5: authentication rejected")
	errNoMethod     = errors.New("socks5: server accepted no offered method")
	errProtocol     = errors.New("socks5: malformed server reply")
	errAddress      = errors.New("socks5: invalid address")
)

// ReplyError is a non-success SOCKS5 reply code.
type ReplyError byte

func (e ReplyError) Error() string { return fmt.Sprintf("socks5: server reply %d", byte(e)) }

// appendAddr encodes ATYP/ADDR/PORT.
func appendAddr(b []byte, a outbound.Addr) ([]byte, error) {
	if ip, ok := a.IP(); ok {
		if ip.Is4() {
			v := ip.As4()
			b = append(append(b, 1), v[:]...)
		} else {
			v := ip.As16()
			b = append(append(b, 4), v[:]...)
		}
	} else {
		if a.Host == "" || len(a.Host) > 255 || strings.ContainsRune(a.Host, 0) {
			return nil, errAddress
		}
		b = append(append(b, 3, byte(len(a.Host))), a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// parseAddr decodes one leading address from b.
func parseAddr(b []byte) (outbound.Addr, int, error) {
	if len(b) < 1 {
		return outbound.Addr{}, 0, errAddress
	}
	var host string
	var end int
	switch b[0] {
	case 1, 4:
		n := 4
		if b[0] == 4 {
			n = 16
		}
		if len(b) < 1+n+2 {
			return outbound.Addr{}, 0, errAddress
		}
		ip, _ := netip.AddrFromSlice(b[1 : 1+n])
		host, end = ip.Unmap().String(), 1+n
	case 3:
		if len(b) < 2 || b[1] == 0 || len(b) < 2+int(b[1])+2 {
			return outbound.Addr{}, 0, errAddress
		}
		host, end = strings.ToLower(string(b[2:2+int(b[1])])), 2+int(b[1])
	default:
		return outbound.Addr{}, 0, errAddress
	}
	return outbound.Addr{Host: host, Port: binary.BigEndian.Uint16(b[end:])}, end + 2, nil
}

func readAddr(r io.Reader) (outbound.Addr, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:1]); e != nil {
		return outbound.Addr{}, e
	}
	var rest []byte
	switch h[0] {
	case 1:
		rest = make([]byte, 4+2)
	case 4:
		rest = make([]byte, 16+2)
	case 3:
		if _, e := io.ReadFull(r, h[1:]); e != nil {
			return outbound.Addr{}, e
		}
		rest = make([]byte, int(h[1])+2)
	default:
		return outbound.Addr{}, errProtocol
	}
	if _, e := io.ReadFull(r, rest); e != nil {
		return outbound.Addr{}, e
	}
	b := append([]byte(nil), h[:1]...)
	if h[0] == 3 {
		b = append(b, h[1])
	}
	a, _, e := parseAddr(append(b, rest...))
	return a, e
}

var aLongTimeAgo = time.Unix(1, 0)

// bounded runs fn with c's deadline bound to ctx (deadline and cancellation).
func bounded(ctx context.Context, c net.Conn, fn func() error) error {
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(aLongTimeAgo) })
	e := fn()
	if !stop() {
		if ce := ctx.Err(); ce != nil {
			return ce
		}
	}
	if e == nil {
		e = c.SetDeadline(time.Time{})
	}
	return e
}

// handshake performs method negotiation, optional RFC1929 auth and one
// request; it returns the bound address of the reply.
func (s *Outbound) handshake(c net.Conn, cmd byte, dst outbound.Addr) (outbound.Addr, error) {
	method := byte(0)
	if s.user != "" {
		method = 2
	}
	if _, e := c.Write([]byte{5, 1, method}); e != nil {
		return outbound.Addr{}, e
	}
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return outbound.Addr{}, e
	}
	if h[0] != 5 {
		return outbound.Addr{}, errProtocol
	}
	if h[1] != method {
		return outbound.Addr{}, errNoMethod
	}
	if method == 2 {
		b := append([]byte{1, byte(len(s.user))}, s.user...)
		b = append(append(b, byte(len(s.pass))), s.pass...)
		if _, e := c.Write(b); e != nil {
			return outbound.Addr{}, e
		}
		if _, e := io.ReadFull(c, h[:]); e != nil {
			return outbound.Addr{}, e
		}
		if h[0] != 1 {
			return outbound.Addr{}, errProtocol
		}
		if h[1] != 0 {
			return outbound.Addr{}, errAuthRejected
		}
	}
	req, e := appendAddr([]byte{5, cmd, 0}, dst)
	if e != nil {
		return outbound.Addr{}, e
	}
	if _, e = c.Write(req); e != nil {
		return outbound.Addr{}, e
	}
	var r [3]byte
	if _, e = io.ReadFull(c, r[:]); e != nil {
		return outbound.Addr{}, e
	}
	if r[0] != 5 || r[2] != 0 {
		return outbound.Addr{}, errProtocol
	}
	if r[1] != 0 {
		return outbound.Addr{}, ReplyError(r[1])
	}
	return readAddr(c)
}

// DialTCP opens a CONNECT tunnel to dst through the proxy.
func (s *Outbound) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	c, e := s.under.DialTCP(ctx, s.server)
	if e != nil {
		return nil, e
	}
	e = bounded(ctx, c, func() error {
		_, e := s.handshake(c, 1, dst)
		return e
	})
	if e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}

// ListenPacket performs UDP ASSOCIATE. The control connection goes through
// under.DialTCP and datagrams through under.ListenPacket; the returned
// PacketConn closes when the control connection ends.
func (s *Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if !s.UDP() {
		return nil, outbound.ErrUDPUnsupported
	}
	ctrl, e := s.under.DialTCP(ctx, s.server)
	if e != nil {
		return nil, e
	}
	var bnd outbound.Addr
	e = bounded(ctx, ctrl, func() error {
		var e error
		bnd, e = s.handshake(ctrl, 3, outbound.Addr{Host: "0.0.0.0", Port: 0})
		return e
	})
	if e != nil {
		ctrl.Close()
		return nil, e
	}
	if bnd.Port == 0 {
		ctrl.Close()
		return nil, errProtocol
	}
	if ip, ok := bnd.IP(); ok && ip.IsUnspecified() {
		bnd.Host = s.server.Host
	}
	pc, e := s.under.ListenPacket(ctx)
	if e != nil {
		ctrl.Close()
		return nil, e
	}
	p := &packetConn{ctrl: ctrl, pc: pc, relay: bnd, done: make(chan struct{})}
	go p.watch()
	return p, nil
}

type packetConn struct {
	ctrl  net.Conn
	pc    outbound.PacketConn
	relay outbound.Addr
	once  sync.Once
	done  chan struct{}
	rbuf  []byte // owned by the single concurrent reader
}

// watch closes the association when the control connection ends.
func (p *packetConn) watch() {
	var b [256]byte
	for {
		if _, e := p.ctrl.Read(b[:]); e != nil {
			p.Close()
			return
		}
	}
}

func (p *packetConn) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	w, e := appendAddr(make([]byte, 3, 3+4+255+len(b)), dst)
	if e != nil {
		return 0, e
	}
	if len(w)+len(b) > 65535 {
		return 0, errors.New("socks5: datagram too large")
	}
	w = append(w, b...)
	if _, e = p.pc.WriteTo(w, p.relay); e != nil {
		return 0, e
	}
	return len(b), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, outbound.Addr, error) {
	if p.rbuf == nil {
		p.rbuf = make([]byte, 65535)
	}
	buf := p.rbuf
	for {
		n, src, e := p.pc.ReadFrom(buf)
		if e != nil {
			select {
			case <-p.done:
				return 0, outbound.Addr{}, net.ErrClosed
			default:
			}
			return 0, outbound.Addr{}, e
		}
		if !p.fromRelay(src) {
			continue
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue // malformed or fragmented: drop
		}
		a, k, e := parseAddr(buf[3:n])
		if e != nil {
			continue
		}
		return copy(b, buf[3+k:n]), a, nil
	}
}

// fromRelay drops datagrams whose (last-hop reported) source is a different
// IP literal than the relay; name-addressed relays cannot be compared.
func (p *packetConn) fromRelay(src outbound.Addr) bool {
	r, ok1 := p.relay.IP()
	s, ok2 := src.IP()
	if !ok1 || !ok2 {
		return true
	}
	return r == s && src.Port == p.relay.Port
}

func (p *packetConn) Close() error {
	p.once.Do(func() {
		close(p.done)
		p.ctrl.Close()
		p.pc.Close()
	})
	return nil
}

func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.pc.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.pc.SetWriteDeadline(t) }
