package anytls

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string                 { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }
func (a Address) MarshalBinary() ([]byte, error) { return a.marshal(false) }
func (a Address) marshal(uot bool) ([]byte, error) {
	if a.Host == "" || strings.ContainsRune(a.Host, 0) {
		return nil, ErrProtocol
	}
	var b []byte
	ip, e := netip.ParseAddr(a.Host)
	if e == nil {
		if ip.Zone() != "" {
			return nil, ErrProtocol
		}
		ip = ip.Unmap()
		if ip.Is4() {
			typ := byte(1)
			if uot {
				typ = 0
			}
			v := ip.As4()
			b = append([]byte{typ}, v[:]...)
		} else {
			typ := byte(4)
			if uot {
				typ = 1
			}
			v := ip.As16()
			b = append([]byte{typ}, v[:]...)
		}
	} else {
		if len(a.Host) > 255 {
			return nil, ErrProtocol
		}
		typ := byte(3)
		if uot {
			typ = 2
		}
		b = append([]byte{typ, byte(len(a.Host))}, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}
func readAddress(r io.Reader, uot bool) (Address, error) {
	var first [1]byte
	if _, e := io.ReadFull(r, first[:]); e != nil {
		return Address{}, e
	}
	typ := first[0]
	ipv4, ipv6, domain := byte(1), byte(4), byte(3)
	if uot {
		ipv4, ipv6, domain = 0, 1, 2
	}
	n := 0
	var host string
	switch typ {
	case ipv4:
		n = 4
	case ipv6:
		n = 16
	case domain:
		if _, e := io.ReadFull(r, first[:]); e != nil {
			return Address{}, unexpected(e)
		}
		n = int(first[0])
		if n == 0 {
			return Address{}, ErrProtocol
		}
	default:
		return Address{}, ErrProtocol
	}
	b := make([]byte, n+2)
	if _, e := io.ReadFull(r, b); e != nil {
		return Address{}, unexpected(e)
	}
	if typ == domain {
		host = string(b[:n])
		if strings.ContainsRune(host, 0) {
			return Address{}, ErrProtocol
		}
	} else {
		ip, ok := netip.AddrFromSlice(b[:n])
		if !ok {
			return Address{}, ErrProtocol
		}
		host = ip.String()
	}
	return Address{host, binary.BigEndian.Uint16(b[n:])}, nil
}
