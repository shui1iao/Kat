package ss

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Address uses SOCKS5 ATYP 1/3/4. Host is owned immutable text: no resolver runs.
// An IPv6 zone, empty host/domain, NUL domain or >255-byte domain is rejected.
type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }
func (a Address) MarshalBinary() ([]byte, error) {
	if a.Host == "" || strings.ContainsRune(a.Host, 0) {
		return nil, ErrFormat
	}
	var b []byte
	if ip, err := netip.ParseAddr(a.Host); err == nil {
		if ip.Zone() != "" {
			return nil, ErrFormat
		}
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append([]byte{1}, v[:]...)
		} else {
			v := ip.As16()
			b = append([]byte{4}, v[:]...)
		}
	} else {
		if len(a.Host) > 255 {
			return nil, ErrFormat
		}
		b = append([]byte{3, byte(len(a.Host))}, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// ParseAddress parses just one leading address, returning the consumed bytes.
// It does not retain or alias input.
func ParseAddress(b []byte) (Address, int, error) {
	if len(b) < 1 {
		return Address{}, 0, io.ErrUnexpectedEOF
	}
	n := 0
	offset := 1
	switch b[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if len(b) < 2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		n = int(b[1])
		offset = 2
		if n == 0 {
			return Address{}, 0, ErrFormat
		}
	default:
		return Address{}, 0, ErrFormat
	}
	end := offset + n
	if len(b) < end+2 {
		return Address{}, 0, io.ErrUnexpectedEOF
	}
	var host string
	if b[0] == 3 {
		host = string(b[offset:end])
		if strings.ContainsRune(host, 0) {
			return Address{}, 0, ErrFormat
		}
	} else {
		ip, ok := netip.AddrFromSlice(b[offset:end])
		if !ok {
			return Address{}, 0, ErrFormat
		}
		host = ip.String()
	}
	return Address{host, binary.BigEndian.Uint16(b[end : end+2])}, end + 2, nil
}
func readAddress(r io.Reader) (Address, error) {
	var prefix [2]byte
	if _, e := io.ReadFull(r, prefix[:1]); e != nil {
		return Address{}, e
	}
	n := 0
	header := prefix[:1]
	switch prefix[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, e := io.ReadFull(r, prefix[1:]); e != nil {
			return Address{}, e
		}
		n = int(prefix[1])
		header = prefix[:]
	default:
		return Address{}, ErrFormat
	}
	b := append([]byte(nil), header...)
	tail := make([]byte, n+2)
	if _, e := io.ReadFull(r, tail); e != nil {
		return Address{}, e
	}
	b = append(b, tail...)
	a, _, e := ParseAddress(b)
	if e != nil {
		return a, fmt.Errorf("%w: address", ErrFormat)
	}
	return a, nil
}
