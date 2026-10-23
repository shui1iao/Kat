package snell

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }
func validHost(h string) bool {
	if len(h) == 0 || len(h) > 255 {
		return false
	}
	if ip, e := netip.ParseAddr(h); e == nil {
		return ip.Zone() == ""
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
func parseConnect(b []byte) (Address, []byte, error) {
	if len(b) < 1 {
		return Address{}, nil, ErrProtocol
	}
	n := int(b[0])
	if len(b) < n+3 {
		return Address{}, nil, ErrProtocol
	}
	a := Address{string(b[1 : 1+n]), binary.BigEndian.Uint16(b[1+n : 3+n])}
	if !validHost(a.Host) || a.Port == 0 {
		return Address{}, nil, ErrProtocol
	}
	return a, b[n+3:], nil
}
func parseDatagram(b []byte) (Address, []byte, error) {
	if len(b) < 2 || b[0] != 1 {
		return Address{}, nil, ErrProtocol
	}
	b = b[1:]
	if b[0] != 0 {
		return parseConnect(b)
	}
	if len(b) < 2 {
		return Address{}, nil, ErrProtocol
	}
	v := b[1]
	n := 0
	if v == 4 {
		n = 4
	} else if v == 6 {
		n = 16
	} else {
		return Address{}, nil, ErrProtocol
	}
	if len(b) < 2+n+2 {
		return Address{}, nil, ErrProtocol
	}
	ip, ok := netip.AddrFromSlice(b[2 : 2+n])
	if !ok {
		return Address{}, nil, ErrProtocol
	}
	a := Address{ip.String(), binary.BigEndian.Uint16(b[2+n : 4+n])}
	if a.Port == 0 {
		return Address{}, nil, ErrProtocol
	}
	return a, b[4+n:], nil
}

// ReadDatagram returns exactly one authenticated record/packet, including a
// possible empty UDP payload. Returned bytes are caller-owned, bounded at 16KiB.
func (q *Request) ReadDatagram() (Address, []byte, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	if q.Command != UDP || q.finished.Load() {
		return Address{}, nil, ErrState
	}
	b, e := q.session.r.next()
	if e != nil {
		q.session.Close()
		return Address{}, nil, e
	}
	a, p, e := parseDatagram(b)
	if e != nil {
		q.session.Close()
	}
	return a, p, e
}

// WriteDatagram replies with a literal source IP, never an unresolved domain.
func (q *Request) WriteDatagram(source Address, p []byte) error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.Command != UDP || !q.approved || q.finished.Load() || q.writeEOF {
		return ErrState
	}
	ip, e := netip.ParseAddr(source.Host)
	if e != nil || ip.Zone() != "" || source.Port == 0 {
		return ErrProtocol
	}
	ip = ip.Unmap()
	n := 4
	v := byte(4)
	if ip.Is6() {
		n = 16
		v = 6
	}
	if len(p) > MaxPayload-3-n {
		return ErrLimit
	}
	if e = q.successLocked(nil); e != nil {
		return e
	}
	b := make([]byte, 1+n+2+len(p))
	b[0] = v
	copy(b[1:], ip.AsSlice())
	binary.BigEndian.PutUint16(b[1+n:], source.Port)
	copy(b[3+n:], p)
	if e = q.session.w.packet(b); e != nil {
		q.session.Close()
	}
	return e
}
