package vlessx

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const VisionFlow = "xtls-rprx-vision"

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }
func validHost(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if p, e := netip.ParseAddr(s); e == nil {
		return p.Zone() == ""
	}
	s = strings.TrimSuffix(s, ".")
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
func readAddress(r io.Reader) (Address, error) {
	var h [3]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return Address{}, e
	}
	a := Address{Port: binary.BigEndian.Uint16(h[:2])}
	n := 0
	switch h[2] {
	case 1:
		n = 4
	case 3:
		n = 16
	case 2:
		var l [1]byte
		if _, e := io.ReadFull(r, l[:]); e != nil {
			return a, e
		}
		n = int(l[0])
	default:
		return a, ErrWire
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return a, e
	}
	if h[2] == 2 {
		a.Host = string(b)
	} else {
		p, ok := netip.AddrFromSlice(b)
		if !ok {
			return a, ErrWire
		}
		a.Host = p.String()
	}
	if !validHost(a.Host) || a.Port == 0 {
		return a, ErrWire
	}
	return a, nil
}
func encodeAddress(a Address) ([]byte, error) {
	if !validHost(a.Host) || a.Port == 0 {
		return nil, ErrWire
	}
	b := []byte{byte(a.Port >> 8), byte(a.Port)}
	p, e := netip.ParseAddr(a.Host)
	if e == nil {
		p = p.Unmap()
		if p.Is4() {
			b = append(b, 1)
		} else {
			b = append(b, 3)
		}
		return append(b, p.AsSlice()...), nil
	}
	b = append(b, 2, byte(len(a.Host)))
	return append(b, a.Host...), nil
}
func varint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < 10 && i < len(b); i++ {
		if i == 9 && b[i] > 1 {
			return 0, 0, ErrWire
		}
		v |= uint64(b[i]&127) << uint(7*i)
		if b[i] < 128 {
			return v, i + 1, nil
		}
	}
	return 0, 0, ErrWire
}

// ParseAddons handles bounded protobuf unknown fields (no unbounded groups).
func ParseAddons(b []byte) (flow string, seed []byte, err error) {
	if len(b) > 255 {
		return "", nil, ErrLimit
	}
	for len(b) > 0 {
		key, n, e := varint(b)
		if e != nil || key>>3 == 0 {
			return "", nil, ErrWire
		}
		b = b[n:]
		field, typ := key>>3, key&7
		if (field == 1 || field == 2) && typ != 2 {
			return "", nil, ErrWire
		}
		switch typ {
		case 0:
			_, n, e = varint(b)
			if e != nil {
				return "", nil, e
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return "", nil, ErrWire
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return "", nil, ErrWire
			}
			b = b[4:]
		case 2:
			l, n, e := varint(b)
			if e != nil || l > uint64(len(b)-n) {
				return "", nil, ErrWire
			}
			v := b[n : n+int(l)]
			b = b[n+int(l):]
			if field == 1 {
				flow = string(v)
			}
			if field == 2 {
				seed = bytes.Clone(v)
			}
		default:
			return "", nil, ErrWire
		}
	}
	return
}

type Request struct {
	UUID    [16]byte
	Command byte
	Target  Address
	Flow    string
	Seed    []byte
}

// ReadRequest authenticates UUID using the caller callback before returning a
// routable request. It consumes only the header; stream bytes remain in r.
func ReadRequest(r io.Reader, authorize func(Request) bool) (Request, error) {
	var q Request
	var h [18]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return q, e
	}
	if h[0] != 0 {
		return q, ErrWire
	}
	copy(q.UUID[:], h[1:17])
	b := make([]byte, int(h[17]))
	if _, e := io.ReadFull(r, b); e != nil {
		return q, e
	}
	var e error
	q.Flow, q.Seed, e = ParseAddons(b)
	if e != nil {
		return q, e
	}
	if q.Flow != "" && q.Flow != VisionFlow {
		return q, ErrUnsupported
	}

	var cmd [1]byte
	if _, e = io.ReadFull(r, cmd[:]); e != nil {
		return q, e
	}
	q.Command = cmd[0]
	switch q.Command {
	case 1, 2:
		q.Target, e = readAddress(r)
	case 3:
	default:
		e = ErrUnsupported
	}
	if q.Flow == VisionFlow && q.Command == 2 {
		return q, ErrUnsupported
	}
	if e != nil {
		return q, e
	}
	if authorize == nil || !authorize(q) {
		return q, ErrState
	}
	return q, nil
}
func WriteResponse(w io.Writer) error { return writeFull(w, []byte{0, 0}) }
