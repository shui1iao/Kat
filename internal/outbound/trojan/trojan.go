// Package trojan is a Trojan client outbound: TLS (outbound.TLSOptions),
// SHA224-hex password authentication, CONNECT and UDP ASSOCIATE carried as
// UDP-over-TLS frames on one TCP stream. Every connection to the server goes
// through the "under" dialer.
package trojan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/internal/tlsclient"
)

const typeName = "trojan"

var errOptions = errors.New("trojan: invalid outbound options")

// Validate checks o statically (no network I/O; reads the CA file if set).
func Validate(o outbound.Options) error {
	_, e := parse(o)
	return e
}

func parse(o outbound.Options) (*tls.Config, error) {
	if o.Type != typeName {
		return nil, fmt.Errorf("%w: type must be %q", errOptions, typeName)
	}
	if o.Name == "" {
		return nil, fmt.Errorf("%w: name required", errOptions)
	}
	if !validServer(o.Server) {
		return nil, fmt.Errorf("%w: server must be an IP literal or a valid domain name", errOptions)
	}
	if o.Port == 0 {
		return nil, fmt.Errorf("%w: port must be 1..65535", errOptions)
	}
	if o.Username != "" || o.Method != "" || o.Key != "" || o.IdleSessions != 0 || o.IdleTimeout != 0 {
		return nil, fmt.Errorf("%w: only server, port, password, tls, udp, via apply to trojan", errOptions)
	}
	if o.Password == "" || len(o.Password) > 4096 {
		return nil, fmt.Errorf("%w: password must be 1..4096 bytes", errOptions)
	}
	if o.TLS == nil {
		return nil, fmt.Errorf("%w: tls block required", errOptions)
	}
	if o.TLS.ServerName != "" && !validServer(o.TLS.ServerName) {
		return nil, fmt.Errorf("%w: invalid tls.server_name", errOptions)
	}
	c, e := o.TLS.ClientConfig(strings.ToLower(o.Server))
	if e != nil {
		return nil, fmt.Errorf("%w: %v", errOptions, e)
	}
	if e := tlsclient.Validate(o.TLS.Fingerprint); e != nil {
		return nil, fmt.Errorf("%w: %v", errOptions, e)
	}
	return c, nil
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

// Outbound is a Trojan client.
type Outbound struct {
	name   string
	server outbound.Addr
	auth   [56]byte
	tls    *tls.Config
	fp     string // uTLS fingerprint ("" = crypto/tls)
	udp    bool
	under  outbound.Dialer
}

var _ outbound.Outbound = (*Outbound)(nil)

// New builds the outbound. It performs no network I/O.
func New(o outbound.Options, under outbound.Dialer) (outbound.Outbound, error) {
	c, e := parse(o)
	if e != nil {
		return nil, e
	}
	if under == nil {
		return nil, fmt.Errorf("%w: nil under dialer", errOptions)
	}
	t := &Outbound{name: o.Name, server: o.ServerAddr(), tls: c, fp: o.TLS.Fingerprint, udp: o.UDPEnabled(), under: under}
	sum := sha256.Sum224([]byte(o.Password))
	hex.Encode(t.auth[:], sum[:])
	return t, nil
}

func (t *Outbound) Name() string { return t.name }
func (t *Outbound) Type() string { return typeName }
func (t *Outbound) Close() error { return nil }

// UDP is carried over the TLS stream, so only the configuration matters.
func (t *Outbound) UDP() bool { return t.udp }

const (
	cmdConnect = 1
	cmdUDP     = 3
	// firstWriteWait: a Read before any Write waits this long for the first
	// payload before sending a header-only request (server-first protocols).
	firstWriteWait = 200 * time.Millisecond
	maxDatagram    = 65535
)

var (
	errAddress = errors.New("trojan: invalid address")
	errFrame   = errors.New("trojan: malformed UDP frame")
)

func (t *Outbound) request(cmd byte, dst outbound.Addr) ([]byte, error) {
	b := make([]byte, 0, 56+2+1+4+255+2+2)
	b = append(append(b, t.auth[:]...), '\r', '\n', cmd)
	b, e := appendAddr(b, dst)
	if e != nil {
		return nil, e
	}
	return append(b, '\r', '\n'), nil
}

func (t *Outbound) handshake(ctx context.Context) (net.Conn, error) {
	raw, e := t.under.DialTCP(ctx, t.server)
	if e != nil {
		return nil, e
	}
	c, e := tlsclient.Handshake(ctx, raw, t.tls, t.fp)
	if e != nil {
		raw.Close()
		return nil, e
	}
	return c, nil
}

// DialTCP completes the TLS handshake; the Trojan request is sent with the
// first Write (or before the first Read/CloseWrite).
func (t *Outbound) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	req, e := t.request(cmdConnect, dst)
	if e != nil {
		return nil, e
	}
	c, e := t.handshake(ctx)
	if e != nil {
		return nil, e
	}
	return &conn{Conn: c, req: req, sentCh: make(chan struct{})}, nil
}

type conn struct {
	net.Conn
	wmu    sync.Mutex
	req    []byte // nil once sent
	sentCh chan struct{}
	werr   error
}

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	if c.req == nil {
		return c.Conn.Write(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	w := append(c.req, p...)
	if _, e := c.Conn.Write(w); e != nil {
		c.werr = e
		return 0, e
	}
	c.req = nil
	close(c.sentCh)
	return len(p), nil
}

func (c *conn) ensureSent() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.req == nil {
		return nil
	}
	if c.werr != nil {
		return c.werr
	}
	if _, e := c.Conn.Write(c.req); e != nil {
		c.werr = e
		return e
	}
	c.req = nil
	close(c.sentCh)
	return nil
}

func (c *conn) Read(p []byte) (int, error) {
	select {
	case <-c.sentCh:
	default:
		t := time.NewTimer(firstWriteWait)
		select {
		case <-c.sentCh:
		case <-t.C:
		}
		t.Stop()
		if e := c.ensureSent(); e != nil {
			return 0, e
		}
	}
	return c.Conn.Read(p)
}

func (c *conn) CloseWrite() error {
	if e := c.ensureSent(); e != nil {
		return e
	}
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

// ListenPacket opens a UDP ASSOCIATE over a new TLS stream. The request
// header (addressed to the first destination) is sent with the first frame.
func (t *Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if !t.udp {
		return nil, outbound.ErrUDPUnsupported
	}
	c, e := t.handshake(ctx)
	if e != nil {
		return nil, e
	}
	return &packetConn{t: t, c: c, r: bufio.NewReaderSize(c, 16384)}, nil
}

type packetConn struct {
	t    *Outbound
	c    net.Conn
	wmu  sync.Mutex
	sent bool
	r    *bufio.Reader
}

func (p *packetConn) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	if len(b) > maxDatagram {
		return 0, errors.New("trojan: datagram too large")
	}
	frame, e := appendAddr(make([]byte, 0, 4+255+2+2+2+len(b)), dst)
	if e != nil {
		return 0, e
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(b)))
	frame = append(append(frame, '\r', '\n'), b...)
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if !p.sent {
		req, e := p.t.request(cmdUDP, dst)
		if e != nil {
			return 0, e
		}
		frame = append(req, frame...)
	}
	if _, e = p.c.Write(frame); e != nil {
		return 0, e
	}
	p.sent = true
	return len(b), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, outbound.Addr, error) {
	src, e := readAddr(p.r)
	if e != nil {
		return 0, outbound.Addr{}, e
	}
	var h [4]byte
	if _, e = io.ReadFull(p.r, h[:]); e != nil {
		return 0, outbound.Addr{}, eofUnexpected(e)
	}
	if h[2] != '\r' || h[3] != '\n' {
		return 0, outbound.Addr{}, errFrame
	}
	n := int(binary.BigEndian.Uint16(h[:2]))
	if n <= len(b) {
		if _, e = io.ReadFull(p.r, b[:n]); e != nil {
			return 0, outbound.Addr{}, eofUnexpected(e)
		}
		return n, src, nil
	}
	// Short buffer: deliver the prefix, discard the rest of this datagram.
	if _, e = io.ReadFull(p.r, b); e != nil {
		return 0, outbound.Addr{}, eofUnexpected(e)
	}
	if _, e = p.r.Discard(n - len(b)); e != nil {
		return 0, outbound.Addr{}, eofUnexpected(e)
	}
	return len(b), src, nil
}

func eofUnexpected(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}

func (p *packetConn) Close() error                       { return p.c.Close() }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.c.SetWriteDeadline(t) }

// appendAddr encodes SOCKS-style ATYP/ADDR/PORT.
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

func readAddr(r io.Reader) (outbound.Addr, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:1]); e != nil {
		return outbound.Addr{}, e
	}
	var n int
	switch h[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, e := io.ReadFull(r, h[1:]); e != nil {
			return outbound.Addr{}, eofUnexpected(e)
		}
		if h[1] == 0 {
			return outbound.Addr{}, errAddress
		}
		n = int(h[1])
	default:
		return outbound.Addr{}, errAddress
	}
	b := make([]byte, n+2)
	if _, e := io.ReadFull(r, b); e != nil {
		return outbound.Addr{}, eofUnexpected(e)
	}
	port := binary.BigEndian.Uint16(b[n:])
	if h[0] == 3 {
		return outbound.Addr{Host: strings.ToLower(string(b[:n])), Port: port}, nil
	}
	ip, _ := netip.AddrFromSlice(b[:n])
	return outbound.Addr{Host: ip.Unmap().String(), Port: port}, nil
}
