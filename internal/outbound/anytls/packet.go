package anytls

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

var errDatagramTooLarge = errors.New("anytls: UDP datagram exceeds 65535 bytes")

// packetConn is UoT v2 in non-connected mode over one logical stream: the
// request is isConnect(0) + SOCKS destination, then every datagram in both
// directions is UoT address + length(2) + payload.
type packetConn struct {
	st *stream

	wmu        sync.Mutex
	headerSent bool

	rmu  sync.Mutex
	rbuf []byte
}

func (c *packetConn) WriteTo(p []byte, dst outbound.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, errDatagramTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	wire := make([]byte, 0, len(p)+2*262+4)
	var e error
	if !c.headerSent {
		wire = append(wire, 0) // non-connected: per-packet addresses
		if wire, e = appendAddr(wire, dst, socksTypes); e != nil {
			return 0, e
		}
	}
	if wire, e = appendAddr(wire, dst, uotTypes); e != nil {
		return 0, e
	}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(p)))
	wire = append(wire, p...)
	if e = c.st.writeData(wire); e != nil {
		return 0, e
	}
	c.headerSent = true
	return len(p), nil
}

// ReadFrom returns exactly one datagram (truncated to len(p)) and its source.
// Partial datagrams survive deadline expiry, so framing never desynchronizes.
func (c *packetConn) ReadFrom(p []byte) (int, outbound.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		src, payload, used, ok, e := parseUoTPacket(c.rbuf)
		if e != nil {
			_ = c.st.Close()
			return 0, outbound.Addr{}, e
		}
		if ok {
			n := copy(p, payload)
			c.rbuf = append(c.rbuf[:0], c.rbuf[used:]...)
			return n, src, nil
		}
		if cap(c.rbuf)-len(c.rbuf) < 16<<10 {
			grown := make([]byte, len(c.rbuf), len(c.rbuf)+64<<10)
			copy(grown, c.rbuf)
			c.rbuf = grown
		}
		n, e := c.st.Read(c.rbuf[len(c.rbuf):cap(c.rbuf)])
		c.rbuf = c.rbuf[:len(c.rbuf)+n]
		if e != nil && n == 0 {
			if e == io.EOF && len(c.rbuf) > 0 {
				e = io.ErrUnexpectedEOF
			}
			return 0, outbound.Addr{}, e
		}
	}
}

func (c *packetConn) Close() error                       { return c.st.Close() }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }

var _ outbound.PacketConn = (*packetConn)(nil)
