package kernel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
)

type request struct {
	Context   context.Context
	UDPRead   func() (packet, error)
	UDPWrite  func(Address, []byte) error
	Reply     func(net.Conn, net.Addr, bool) error
	Command   byte
	Target    Address
	Mode      string
	UserIndex int      // -1 for intentionally unauthenticated loopback SOCKS
	Stream    net.Conn // optional transforming stream; never expose raw TCP if transforms remain
	Datagrams datagramCodec
}
type adapter func(net.Conn, Inbound) (request, error)

var adapters = map[string]adapter{"socks5": parseSOCKS, "trojan": parseTrojan, "vless": parseVLESS}

func (r request) respond(c net.Conn, bound net.Addr, ok bool) error {
	if r.Reply != nil {
		return r.Reply(c, bound, ok)
	}
	switch r.Mode {
	case "socks5":
		rep := byte(0)
		if !ok {
			rep = 5
		}
		a := Address{"0.0.0.0", 0}
		if bound != nil {
			a = addrFromNet(bound)
		}
		return writeAll(c, appendAddress([]byte{5, rep, 0}, a, false))
	case "vless":
		if ok {
			return writeAll(c, []byte{0, 0})
		}
	}
	return nil
}
func parseSOCKS(c net.Conn, in Inbound) (request, error) {
	r := request{Mode: "socks5", UserIndex: -1}
	h, e := readN(c, 2)
	if e != nil {
		return r, e
	}
	if h[0] != 5 || h[1] == 0 {
		return r, errors.New("invalid SOCKS greeting")
	}
	methods, e := readN(c, int(h[1]))
	if e != nil {
		return r, e
	}
	method := byte(0)
	if len(in.Users) > 0 {
		method = 2
	}
	found := false
	for _, v := range methods {
		if v == method {
			found = true
		}
	}
	if !found {
		_ = writeAll(c, []byte{5, 255})
		return r, errors.New("no supported authentication method")
	}
	if e = writeAll(c, []byte{5, method}); e != nil {
		return r, e
	}
	if method == 2 {
		v, e := readN(c, 2)
		if e != nil {
			return r, e
		}
		if v[0] != 1 || v[1] == 0 {
			return r, errors.New("invalid authentication version or username")
		}
		u, e := readN(c, int(v[1]))
		if e != nil {
			return r, e
		}
		n, e := readN(c, 1)
		if e != nil {
			return r, e
		}
		if n[0] == 0 {
			return r, errors.New("empty password")
		}
		p, e := readN(c, int(n[0]))
		if e != nil {
			return r, e
		}
		providedUser := sha256.Sum256(u)
		providedPass := sha256.Sum256(p)
		match := 0
		for i, usr := range in.Users {
			expectedUser := sha256.Sum256([]byte(usr.Username))
			expectedPass := sha256.Sum256([]byte(usr.Password))
			m := subtle.ConstantTimeCompare(providedUser[:], expectedUser[:]) & subtle.ConstantTimeCompare(providedPass[:], expectedPass[:])
			match |= m
			if m == 1 {
				r.UserIndex = i
			}
		}
		status := byte(0)
		if match == 0 {
			status = 1
		}
		if e = writeAll(c, []byte{1, status}); e != nil {
			return r, e
		}
		if match == 0 {
			return r, errors.New("authentication failed")
		}
	}
	h, e = readN(c, 3)
	if e != nil {
		return r, e
	}
	if h[0] != 5 || h[2] != 0 {
		return r, errors.New("invalid SOCKS request")
	}
	r.Command = h[1]
	if r.Command != 1 && r.Command != 3 {
		_ = writeAll(c, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return r, errors.New("unsupported SOCKS command")
	}
	r.Target, e = readAddress(c, false)
	if e != nil {
		_ = writeAll(c, []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return r, e
	}
	return r, nil
}
func expectCRLF(r io.Reader) error {
	b, e := readN(r, 2)
	if e != nil {
		return e
	}
	if b[0] != 13 || b[1] != 10 {
		return errors.New("invalid CRLF")
	}
	return nil
}
func parseTrojan(c net.Conn, in Inbound) (request, error) {
	r := request{Mode: "trojan", UserIndex: -1, Datagrams: trojanDatagrams{}}
	b, e := readN(c, 56)
	if e != nil {
		return r, e
	}
	match := 0
	for i, u := range in.Users {
		sum := sha256.Sum224([]byte(u.Password))
		var encoded [56]byte
		hex.Encode(encoded[:], sum[:])
		m := subtle.ConstantTimeCompare(b, encoded[:])
		match |= m
		if m == 1 {
			r.UserIndex = i
		}
	}
	if match == 0 {
		return r, errors.New("authentication failed")
	}
	if e = expectCRLF(c); e != nil {
		return r, e
	}
	v, e := readN(c, 1)
	if e != nil {
		return r, e
	}
	r.Command = v[0]
	if r.Command != 1 && r.Command != 3 {
		return r, errors.New("unsupported Trojan command")
	}
	r.Target, e = readAddress(c, false)
	if e != nil {
		return r, e
	}
	return r, expectCRLF(c)
}
func parseVLESS(c net.Conn, in Inbound) (request, error) {
	r := request{Mode: "vless", UserIndex: -1, Datagrams: vlessDatagrams{}}
	b, e := readN(c, 18)
	if e != nil {
		return r, e
	}
	if b[0] != 0 {
		return r, errors.New("unsupported VLESS wire version")
	}
	match := 0
	for i, u := range in.Users {
		uuid, _ := parseUUID(u.UUID)
		m := subtle.ConstantTimeCompare(b[1:17], uuid[:])
		match |= m
		if m == 1 {
			r.UserIndex = i
		}
	}
	if match == 0 {
		return r, errors.New("authentication failed")
	}
	addons, e := readN(c, int(b[17]))
	if e != nil {
		return r, e
	}
	if e = validateAddons(addons); e != nil {
		return r, e
	}
	cmd, e := readN(c, 1)
	if e != nil {
		return r, e
	}
	r.Command = cmd[0]
	if r.Command != 1 && r.Command != 2 {
		return r, errors.New("unsupported VLESS command")
	}
	port, e := readN(c, 2)
	if e != nil {
		return r, e
	}
	r.Target, e = readHost(c, true)
	r.Target.Port = binary.BigEndian.Uint16(port)
	if e != nil {
		return r, e
	}
	if r.Command == 2 {
		r.Command = 3
	}
	return r, nil
}

// Minimal protobuf wire reader: known nonempty flow/seed rejected; well-formed
// unknown varint/fixed/bytes fields skipped. Groups are deliberately unsupported.
func validateAddons(b []byte) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 || key>>3 == 0 || key>>3 > 1<<29-1 {
			return errors.New("invalid addons key")
		}
		b = b[n:]
		field, wire := key>>3, key&7
		if (field == 1 || field == 2) && wire != 2 {
			return errors.New("invalid known addons field type")
		}
		switch wire {
		case 0:
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return errors.New("invalid addons varint")
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return io.ErrUnexpectedEOF
			}
			b = b[8:]
		case 2:
			length, k := binary.Uvarint(b)
			if k <= 0 || length > uint64(len(b)-max(k, 0)) {
				return errors.New("invalid addons length")
			}
			b = b[k:]
			if (field == 1 || field == 2) && length > 0 {
				return errors.New("VLESS flow/encryption not implemented")
			}
			b = b[int(length):]
		case 5:
			if len(b) < 4 {
				return io.ErrUnexpectedEOF
			}
			b = b[4:]
		default:
			return errors.New("unsupported addons wire type")
		}
	}
	return nil
}
