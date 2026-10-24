package ss

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

const (
	maxChunk2017 = 0x3fff
	maxChunk2022 = 0xffff
	tagSize      = 16
	maxPadding   = 900
)

var (
	errAuth     = errors.New("shadowsocks: authentication failed (wrong key/password or not a shadowsocks server)")
	errFormat   = errors.New("shadowsocks: malformed server message")
	errTime     = errors.New("shadowsocks: server timestamp outside 30-second window")
	errSalt     = errors.New("shadowsocks: response does not echo the request salt")
	errAddress  = errors.New("shadowsocks: invalid address")
	errExhaust  = errors.New("shadowsocks: nonce exhausted")
	errTooLarge = errors.New("shadowsocks: datagram too large")
)

// Outbound is a Shadowsocks client.
type Outbound struct {
	name   string
	m      method
	key    []byte
	server outbound.Addr
	udp    bool
	under  outbound.Dialer
	// SS2022 UDP: PSK-keyed header block (AES variants) / XChaCha AEAD (chacha).
	udpBlock cipher.Block
	udpX     cipher.AEAD
	now      func() time.Time
}

var _ outbound.Outbound = (*Outbound)(nil)

// New builds the outbound. It performs no network I/O.
func New(o outbound.Options, under outbound.Dialer) (outbound.Outbound, error) {
	m, key, e := parse(o)
	if e != nil {
		return nil, e
	}
	if under == nil {
		return nil, fmt.Errorf("%w: nil under dialer", errOptions)
	}
	s := &Outbound{name: o.Name, m: m, key: key, server: o.ServerAddr(), udp: o.UDPEnabled(), under: under, now: time.Now}
	if m.v2022 {
		if m.chacha {
			s.udpX, e = newXChaCha(key)
		} else {
			s.udpBlock, e = newAESBlock(key)
		}
		if e != nil {
			return nil, e
		}
	}
	return s, nil
}

func (s *Outbound) Name() string { return s.name }
func (s *Outbound) Type() string { return typeName }
func (s *Outbound) Close() error { return nil }
func (s *Outbound) UDP() bool    { return s.udp && s.under.UDP() }

// DialTCP connects to the server through under. The request header is sent
// lazily with the first Write (or before the first Read/CloseWrite, for
// server-first protocols), so salt+headers+first payload share one write.
func (s *Outbound) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	addr, e := appendAddr(nil, dst)
	if e != nil {
		return nil, e
	}
	c, e := s.under.DialTCP(ctx, s.server)
	if e != nil {
		return nil, e
	}
	return &tcpConn{Conn: c, s: s, addr: addr, sentCh: make(chan struct{})}, nil
}

// firstWriteWait is how long a Read issued before any Write waits for the
// first payload before sending a header-only request (server-first protocols).
const firstWriteWait = 200 * time.Millisecond

type nonce [12]byte

func (n *nonce) next() (bool, []byte) {
	cur := *n
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return true, cur[:]
		}
	}
	// Wrapped: the value just returned was the last usable one.
	return false, cur[:]
}

type tcpConn struct {
	net.Conn
	s    *Outbound
	addr []byte

	wmu     sync.Mutex
	sent    bool
	sentCh  chan struct{} // closed once the request header is on the wire
	reqSalt []byte
	enc     cipher.AEAD
	wn      nonce
	wdead   bool
	werr    error

	rmu     sync.Mutex
	dec     cipher.AEAD
	rn      nonce
	rdead   bool
	pending []byte
	rerr    error
}

func (c *tcpConn) seal(dst, p []byte) ([]byte, error) {
	if c.wdead {
		return nil, errExhaust
	}
	ok, n := c.wn.next()
	c.wdead = !ok
	return c.enc.Seal(dst, n, p, nil), nil
}

func (c *tcpConn) open(p []byte) ([]byte, error) {
	if c.rdead {
		return nil, errExhaust
	}
	ok, n := c.rn.next()
	c.rdead = !ok
	out, e := c.dec.Open(p[:0], n, p, nil)
	if e != nil {
		return nil, errAuth
	}
	return out, nil
}

func (c *tcpConn) maxChunk() int {
	if c.s.m.v2022 {
		return maxChunk2022
	}
	return maxChunk2017
}

// appendChunks seals p as length-prefixed records.
func (c *tcpConn) appendChunks(w, p []byte) ([]byte, error) {
	for len(p) > 0 {
		n := min(len(p), c.maxChunk())
		var e error
		if w, e = c.seal(w, []byte{byte(n >> 8), byte(n)}); e != nil {
			return nil, e
		}
		if w, e = c.seal(w, p[:n]); e != nil {
			return nil, e
		}
		p = p[n:]
	}
	return w, nil
}

func randInt(lo, hi int) int {
	v, e := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if e != nil {
		return hi
	}
	return lo + int(v.Int64())
}

// header builds salt+request header carrying as much of p as possible, and
// returns the wire and the number of payload bytes consumed. The caller holds wmu.
func (c *tcpConn) header(p []byte) ([]byte, int, error) {
	m := c.s.m
	salt := make([]byte, m.keySize)
	if _, e := rand.Read(salt); e != nil {
		return nil, 0, e
	}
	var e error
	if c.enc, e = sessionAEAD(m, c.s.key, salt); e != nil {
		return nil, 0, e
	}
	c.reqSalt = salt
	w := make([]byte, 0, len(salt)+64+len(c.addr)+len(p)+(len(p)/maxChunk2017+2)*2*tagSize)
	w = append(w, salt...)
	if !m.v2022 {
		first := make([]byte, 0, len(c.addr)+len(p))
		first = append(append(first, c.addr...), p...)
		w, e = c.appendChunks(w, first)
		return w, len(p), e
	}
	padding := 0
	if len(p) == 0 {
		padding = randInt(1, maxPadding)
	}
	take := min(len(p), maxChunk2022-len(c.addr)-2-padding)
	variable := make([]byte, 0, len(c.addr)+2+padding+take)
	variable = append(variable, c.addr...)
	variable = binary.BigEndian.AppendUint16(variable, uint16(padding))
	if padding > 0 {
		pad := make([]byte, padding)
		if _, e = rand.Read(pad); e != nil {
			return nil, 0, e
		}
		variable = append(variable, pad...)
	}
	variable = append(variable, p[:take]...)
	now := c.s.now().Unix()
	if now < 0 {
		return nil, 0, errTime
	}
	fixed := make([]byte, 0, 11)
	fixed = append(fixed, 0)
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(now))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))
	if w, e = c.seal(w, fixed); e != nil {
		return nil, 0, e
	}
	w, e = c.seal(w, variable)
	return w, take, e
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Write encrypts p. The first call sends salt+fixed+variable header (+payload)
// in exactly one underlying Write (SIP022 servers require the initial salt and
// fixed header in one read).
func (c *tcpConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	if !c.sent {
		w, n, e := c.header(p)
		if e == nil {
			e = writeFull(c.Conn, w)
		}
		if e != nil {
			c.werr = e
			return 0, e
		}
		c.sent = true
		close(c.sentCh)
		total, p = n, p[n:]
	}
	const batch = 4 * maxChunk2017
	for len(p) > 0 {
		n := min(len(p), batch)
		w, e := c.appendChunks(make([]byte, 0, n+(n/maxChunk2017+1)*(2+2*tagSize)), p[:n])
		if e == nil {
			e = writeFull(c.Conn, w)
		}
		if e != nil {
			c.werr = e
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// ensureSent sends the request header without payload (with random padding
// for SIP022) when nothing has been written yet.
func (c *tcpConn) ensureSent() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.sent {
		return nil
	}
	if c.werr != nil {
		return c.werr
	}
	w, _, e := c.header(nil)
	if e == nil {
		e = writeFull(c.Conn, w)
	}
	if e != nil {
		c.werr = e
		return e
	}
	c.sent = true
	close(c.sentCh)
	return nil
}

func (c *tcpConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
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
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if e := c.readRecord(); e != nil {
			c.rerr = e
			c.pending = nil
			return 0, e
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *tcpConn) readFull(n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(c.Conn, b)
	return b, e
}

func eofUnexpected(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}

// readRecord reads the response salt/header on first use, then one record.
func (c *tcpConn) readRecord() error {
	m := c.s.m
	if c.dec == nil {
		salt, e := c.readFull(m.keySize)
		if e != nil {
			return e
		}
		if c.dec, e = sessionAEAD(m, c.s.key, salt); e != nil {
			return e
		}
		if m.v2022 {
			b, e := c.readFull(1 + 8 + m.keySize + 2 + tagSize)
			if e != nil {
				return eofUnexpected(e)
			}
			h, e := c.open(b)
			if e != nil {
				return e
			}
			if h[0] != 1 {
				return errFormat
			}
			if !checkTime(binary.BigEndian.Uint64(h[1:9]), c.s.now()) {
				return errTime
			}
			c.wmu.Lock()
			req := c.reqSalt
			c.wmu.Unlock()
			if subtle.ConstantTimeCompare(h[9:9+m.keySize], req) != 1 {
				return errSalt
			}
			return c.readPayload(int(binary.BigEndian.Uint16(h[9+m.keySize:])))
		}
	}
	b, e := c.readFull(2 + tagSize)
	if e != nil {
		return e
	}
	h, e := c.open(b)
	if e != nil {
		return e
	}
	length := int(binary.BigEndian.Uint16(h))
	if length > c.maxChunk() {
		return errFormat
	}
	return c.readPayload(length)
}

func (c *tcpConn) readPayload(length int) error {
	b, e := c.readFull(length + tagSize)
	if e != nil {
		return eofUnexpected(e)
	}
	c.pending, e = c.open(b)
	return e
}

// CloseWrite sends the header if needed, then half-closes the transport.
func (c *tcpConn) CloseWrite() error {
	if e := c.ensureSent(); e != nil {
		return e
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("shadowsocks: transport does not support CloseWrite")
}

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
