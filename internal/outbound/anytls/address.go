package anytls

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"github.com/shui1iao/Kat/internal/outbound"
)

var errAddress = errors.New("anytls: unencodable destination address")

// Stream targets use the SOCKS address form (1=IPv4, 3=domain, 4=IPv6); UoT v2
// per-packet addresses use 0=IPv4, 1=IPv6, 2=domain.
type addrTypes struct{ v4, v6, domain byte }

var (
	socksTypes = addrTypes{1, 4, 3}
	uotTypes   = addrTypes{0, 1, 2}
)

func appendAddr(b []byte, a outbound.Addr, t addrTypes) ([]byte, error) {
	if a.Host == "" {
		return nil, errAddress
	}
	if ip, e := netip.ParseAddr(a.Host); e == nil {
		if ip.Zone() != "" {
			return nil, errAddress
		}
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append(append(b, t.v4), v[:]...)
		} else {
			v := ip.As16()
			b = append(append(b, t.v6), v[:]...)
		}
	} else {
		if len(a.Host) > 255 || strings.ContainsAny(a.Host, "\x00%") {
			return nil, errAddress
		}
		b = append(append(b, t.domain, byte(len(a.Host))), a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// parseUoTPacket parses one non-connected UoT v2 datagram from b. ok is false
// when b does not yet hold a whole datagram.
func parseUoTPacket(b []byte) (src outbound.Addr, payload []byte, used int, ok bool, err error) {
	if len(b) < 1 {
		return src, nil, 0, false, nil
	}
	var hostLen, off int
	switch b[0] {
	case uotTypes.v4:
		hostLen, off = 4, 1
	case uotTypes.v6:
		hostLen, off = 16, 1
	case uotTypes.domain:
		if len(b) < 2 {
			return src, nil, 0, false, nil
		}
		hostLen, off = int(b[1]), 2
		if hostLen == 0 {
			return src, nil, 0, false, errProtocol
		}
	default:
		return src, nil, 0, false, errProtocol
	}
	head := off + hostLen + 2 + 2
	if len(b) < head {
		return src, nil, 0, false, nil
	}
	n := int(binary.BigEndian.Uint16(b[head-2 : head]))
	if len(b) < head+n {
		return src, nil, 0, false, nil
	}
	raw := b[off : off+hostLen]
	if b[0] == uotTypes.domain {
		if strings.ContainsRune(string(raw), 0) {
			return src, nil, 0, false, errProtocol
		}
		src.Host = strings.ToLower(string(raw))
	} else {
		ip, _ := netip.AddrFromSlice(raw)
		src.Host = ip.Unmap().String()
	}
	src.Port = binary.BigEndian.Uint16(b[off+hostLen : off+hostLen+2])
	return src, b[head : head+n], head + n, true, nil
}
