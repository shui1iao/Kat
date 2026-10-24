package anytls

import (
	"crypto/md5" // Wire padding-scheme fingerprint required by the protocol, not security.
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"unicode/utf8"
)

var errPaddingScheme = errors.New("anytls: invalid padding scheme")

// sizeSpec is one comma-separated token of a padding rule: a record size range
// "lo-hi" or the checkpoint "c" (stop padding this packet when no payload is left).
type sizeSpec struct {
	lo, hi int
	check  bool
}

// paddingScheme is the parsed form of the protocol's padding scheme text:
// "stop=N" plus "<packet index>=<token>,<token>..." lines. Packet 0 is the
// authentication packet (its first size is the padding0 length); packets
// 1..stop-1 are the following session writes, split into records of the given
// sizes and topped up with waste frames.
type paddingScheme struct {
	raw     string
	md5     string
	stop    int
	packets map[int][]sizeSpec
}

const checkMark = -1

func parsePaddingScheme(raw string) (*paddingScheme, error) {
	if raw == "" || len(raw) > 65535 || !utf8.ValidString(raw) {
		return nil, errPaddingScheme
	}
	p := &paddingScheme{raw: raw, stop: -1, packets: make(map[int][]sizeSpec)}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errPaddingScheme
		}
		if key == "stop" {
			n, e := strconv.Atoi(value)
			if e != nil || n < 1 || n > 1024 || p.stop >= 0 {
				return nil, errPaddingScheme
			}
			p.stop = n
			continue
		}
		index, e := strconv.Atoi(key)
		if e != nil || index < 0 || index > 1023 {
			return nil, errPaddingScheme
		}
		if _, dup := p.packets[index]; dup {
			return nil, errPaddingScheme
		}
		tokens := strings.Split(value, ",")
		if len(tokens) > 64 {
			return nil, errPaddingScheme
		}
		specs := make([]sizeSpec, 0, len(tokens))
		for _, token := range tokens {
			if token == "c" {
				specs = append(specs, sizeSpec{check: true})
				continue
			}
			a, b, ok := strings.Cut(token, "-")
			if !ok {
				return nil, errPaddingScheme
			}
			lo, e1 := strconv.Atoi(a)
			hi, e2 := strconv.Atoi(b)
			if e1 != nil || e2 != nil || lo < 0 || hi < 0 || lo > 65535 || hi > 65535 {
				return nil, errPaddingScheme
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			specs = append(specs, sizeSpec{lo: lo, hi: hi})
		}
		p.packets[index] = specs
	}
	if p.stop < 0 {
		return nil, errPaddingScheme
	}
	sum := md5.Sum([]byte(raw))
	p.md5 = hex.EncodeToString(sum[:])
	return p, nil
}

// sizes samples the record sizes for one packet; checkMark marks a checkpoint.
// Zero sizes are skipped (they describe no record).
func (p *paddingScheme) sizes(packet int) []int {
	if packet >= p.stop {
		return nil
	}
	specs := p.packets[packet]
	out := make([]int, 0, len(specs))
	for _, s := range specs {
		switch {
		case s.check:
			out = append(out, checkMark)
		case s.hi <= 0:
		case s.lo == s.hi:
			out = append(out, s.lo)
		default:
			out = append(out, s.lo+rand.IntN(s.hi-s.lo+1))
		}
	}
	return out
}

// authPadding is the padding0 length of the authentication packet.
func (p *paddingScheme) authPadding() int {
	for _, n := range p.sizes(0) {
		if n > 0 {
			return n
		}
	}
	return 0
}
