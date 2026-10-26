package sniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// QUIC versions with public Initial keys.
const (
	quicV1      = 0x00000001
	quicV2      = 0x6b3343cf
	quicDraft29 = 0xff00001d
)

var (
	saltV1      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2      = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	saltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
)

// maxCrypto bounds the reassembled ClientHello of a QUIC Initial.
const maxCrypto = 16 << 10

// QUIC reassembles the CRYPTO stream of client Initial packets (a
// ClientHello may span several Initial packets and arrive as out-of-order
// CRYPTO frames) until the ClientHello is complete.
type QUIC struct {
	buf  []byte
	have []bool
	hi   int
}

var errNotInitial = errors.New("sniff: not a QUIC Initial")

// IsInitial reports whether p looks like a QUIC long-header Initial packet
// of a supported version (no decryption).
func IsInitial(p []byte) bool {
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(p[1:5])
	t := (p[0] >> 4) & 3
	switch v {
	case quicV1, quicDraft29:
		return t == 0
	case quicV2:
		return t == 1
	}
	return false
}

// Add feeds one UDP datagram. It returns Done with the SNI once the
// ClientHello is complete, NeedMore while it is not, NotMatch when the
// datagram is not a decryptable client Initial.
func (q *QUIC) Add(p []byte) (string, Status) {
	if !IsInitial(p) {
		return "", NotMatch
	}
	frames, err := openInitial(p)
	if err != nil {
		return "", NotMatch
	}
	if !q.frames(frames) {
		return "", NotMatch
	}
	// Contiguous prefix?
	n := 0
	for n < q.hi && q.have[n] {
		n++
	}
	if n < 4 {
		return "", NeedMore
	}
	if q.buf[0] != 1 {
		return "", NotMatch
	}
	total := 4 + (int(q.buf[1])<<16 | int(q.buf[2])<<8 | int(q.buf[3]))
	if total > maxCrypto {
		return "", NotMatch
	}
	if n < total {
		return "", NeedMore
	}
	host, st := ClientHelloSNI(q.buf[:total])
	if st != Done {
		return "", NotMatch
	}
	return host, Done
}

func readVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l, true
}

// frames walks the decrypted Initial payload and stores CRYPTO data.
func (q *QUIC) frames(b []byte) bool {
	for len(b) > 0 {
		t := b[0]
		switch {
		case t == 0x00: // PADDING
			b = b[1:]
		case t == 0x01: // PING
			b = b[1:]
		case t == 0x02 || t == 0x03: // ACK
			b = b[1:]
			var ok bool
			var n, cnt uint64
			var l int
			for i := 0; i < 2; i++ { // largest, delay
				if _, l, ok = readVarint(b); !ok {
					return false
				}
				b = b[l:]
			}
			if cnt, l, ok = readVarint(b); !ok {
				return false
			}
			b = b[l:]
			if _, l, ok = readVarint(b); !ok { // first range
				return false
			}
			b = b[l:]
			for i := uint64(0); i < cnt*2; i++ {
				if n, l, ok = readVarint(b); !ok {
					return false
				}
				_ = n
				b = b[l:]
			}
			if t == 0x03 {
				for i := 0; i < 3; i++ {
					if _, l, ok = readVarint(b); !ok {
						return false
					}
					b = b[l:]
				}
			}
		case t == 0x06: // CRYPTO
			b = b[1:]
			off, l1, ok := readVarint(b)
			if !ok {
				return false
			}
			b = b[l1:]
			ln, l2, ok := readVarint(b)
			if !ok || ln > uint64(len(b)-l2) {
				return false
			}
			b = b[l2:]
			if off+ln > maxCrypto {
				return false
			}
			end := int(off + ln)
			if end > len(q.buf) {
				nb := make([]byte, end)
				copy(nb, q.buf)
				q.buf = nb
				nh := make([]bool, end)
				copy(nh, q.have)
				q.have = nh
			}
			copy(q.buf[off:end], b[:ln])
			for i := int(off); i < end; i++ {
				q.have[i] = true
			}
			q.hi = max(q.hi, end)
			b = b[ln:]
		case t == 0x1c: // CONNECTION_CLOSE: not a ClientHello flight
			return false
		default:
			return false
		}
	}
	return true
}

func expandLabel(secret []byte, label string, n int) []byte {
	info := make([]byte, 0, 4+6+len(label))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(6+len(label)))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

// openInitial removes header protection and decrypts the first (Initial)
// packet of the datagram, returning its frames.
func openInitial(p []byte) ([]byte, error) {
	version := binary.BigEndian.Uint32(p[1:5])
	salt, kl, il, hl := saltV1, "quic key", "quic iv", "quic hp"
	switch version {
	case quicV2:
		salt, kl, il, hl = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	case quicDraft29:
		salt = saltDraft29
	}
	b := p[5:]
	dl := int(b[0])
	if dl > 20 || len(b) < 1+dl+1 {
		return nil, errNotInitial
	}
	dcid := b[1 : 1+dl]
	b = b[1+dl:]
	sl := int(b[0])
	if sl > 20 || len(b) < 1+sl {
		return nil, errNotInitial
	}
	b = b[1+sl:]
	tl, n, ok := readVarint(b)
	if !ok || tl > uint64(len(b)-n) {
		return nil, errNotInitial
	}
	b = b[n+int(tl):]
	length, n, ok := readVarint(b)
	if !ok || length > uint64(len(b)-n) || length < 20 {
		return nil, errNotInitial
	}
	pnOff := len(p) - len(b) + n
	packet := p[:pnOff+int(length)]

	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, err
	}
	client := expandLabel(initial, "client in", 32)
	key := expandLabel(client, kl, 16)
	iv := expandLabel(client, il, 12)
	hp := expandLabel(client, hl, 16)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	if pnOff+4+16 > len(packet) {
		return nil, errNotInitial
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], packet[pnOff+4:pnOff+4+16])
	hdr := make([]byte, pnOff+4)
	copy(hdr, packet[:pnOff+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	return aead.Open(nil, nonce, packet[pnOff+pnLen:], hdr)
}
