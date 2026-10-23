package anytls

import (
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// DatagramConn adapts UoT v2, not native UDP and not UoT v1. In connected mode
// both directions implicitly use Target. In non-connected mode per-packet
// ATYP is 0=IPv4/1=IPv6/2=domain, distinct from the SOCKS request header's 1/4/3.
// Do not mix raw Stream reads/writes with this adapter.
type DatagramConn struct {
	stream    *Stream
	connected bool
	target    Address
	rMu, wMu  sync.Mutex
}

func newDatagram(st *Stream) (*DatagramConn, error) {
	var b [1]byte
	if _, e := io.ReadFull(st, b[:]); e != nil {
		return nil, unexpected(e)
	}
	if b[0] > 1 {
		return nil, ErrProtocol
	}
	target, e := readAddress(st, false)
	if e != nil {
		return nil, e
	}
	return &DatagramConn{stream: st, connected: b[0] == 1, target: target}, nil
}
func (d *DatagramConn) Connected() bool { return d.connected }
func (d *DatagramConn) Target() Address { return d.target }

// ReadPacket owns a new payload (including zero-length UDP datagrams).
func (d *DatagramConn) ReadPacket() (Address, []byte, error) {
	d.rMu.Lock()
	defer d.rMu.Unlock()
	target := d.target
	if !d.connected {
		var e error
		target, e = readAddress(d.stream, true)
		if e != nil {
			return Address{}, nil, e
		}
	}
	var length [2]byte
	if _, e := io.ReadFull(d.stream, length[:]); e != nil {
		if !d.connected {
			e = unexpected(e)
		}
		return Address{}, nil, e
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	payload := make([]byte, n)
	if _, e := io.ReadFull(d.stream, payload); e != nil {
		return Address{}, nil, unexpected(e)
	}
	return target, payload, nil
}

// WritePacket enforces the fixed connected address because that wire mode has no
// per-packet source field. For a domain resolved by the router, pass Target() for
// connected responses, not an unrepresentable resolved-IP source address.
func (d *DatagramConn) WritePacket(from Address, payload []byte) error {
	if len(payload) > 65535 {
		return ErrProtocol
	}
	d.wMu.Lock()
	defer d.wMu.Unlock()
	var header []byte
	if d.connected {
		if from != d.target {
			return ErrConnectedAddress
		}
	} else {
		var e error
		header, e = from.marshal(true)
		if e != nil {
			return e
		}
	}
	header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	wire := append(header, payload...)
	n, e := d.stream.Write(wire)
	if e == nil && n != len(wire) {
		e = io.ErrShortWrite
	}
	return e
}
func (d *DatagramConn) Close() error                       { return d.stream.Close() }
func (d *DatagramConn) SetReadDeadline(t time.Time) error  { return d.stream.SetReadDeadline(t) }
func (d *DatagramConn) SetWriteDeadline(t time.Time) error { return d.stream.SetWriteDeadline(t) }
