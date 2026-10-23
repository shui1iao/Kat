package kernel

import (
	"encoding/binary"
	"errors"
	"io"
)

// datagramCodec is frame-only: one owned payload per successful read and no
// background work. UDP association lifetime, quotas and return filtering remain shared.
type datagramCodec interface {
	ReadPacket(io.Reader, Address) (packet, error)
	AppendPacket([]byte, Address, []byte) []byte
}
type trojanDatagrams struct{}
type vlessDatagrams struct{}

func readDatagramBody(r io.Reader, crlf bool) ([]byte, error) {
	b, e := readN(r, 2)
	if e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > maxDatagram {
		return nil, errors.New("UDP frame too large")
	}
	if crlf {
		if e = expectCRLF(r); e != nil {
			return nil, e
		}
	}
	return readN(r, n)
}
func (trojanDatagrams) ReadPacket(r io.Reader, _ Address) (packet, error) {
	a, e := readAddress(r, false)
	if e != nil {
		return packet{}, e
	}
	b, e := readDatagramBody(r, true)
	return packet{a, b}, e
}
func (trojanDatagrams) AppendPacket(b []byte, a Address, p []byte) []byte {
	b = appendAddress(b, a, false)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	b = append(b, 13, 10)
	return append(b, p...)
}
func (vlessDatagrams) ReadPacket(r io.Reader, a Address) (packet, error) {
	b, e := readDatagramBody(r, false)
	return packet{a, b}, e
}
func (vlessDatagrams) AppendPacket(b []byte, _ Address, p []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}
