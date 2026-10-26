package route

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

var (
	errParse     = errors.New("route: content is not a valid rule set or database")
	errLimit     = errors.New("route: entry limit exceeded")
	errTooLarge  = errors.New("route: content exceeds max_bytes")
	errNoResolve = errors.New("route: no resolver")
	// ErrNoAddress is returned when the resolver succeeded but produced no
	// usable address for a destination that must be dialed directly.
	ErrNoAddress = errors.New("route: no address for destination")
)

// ---- IP ranges: sorted, merged, binary-searched; IPv4 and IPv6 separate ----

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }
func (a u128) inc() (u128, bool) { // a+1, overflow
	if a.lo != ^uint64(0) {
		return u128{a.hi, a.lo + 1}, false
	}
	if a.hi != ^uint64(0) {
		return u128{a.hi + 1, 0}, false
	}
	return u128{}, true
}
func addr128(ip netip.Addr) u128 {
	b := ip.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

type r4 struct{ lo, hi uint32 }
type r6 struct{ lo, hi u128 }

type ipSet struct {
	v4 []r4
	v6 []r6
}

func (s *ipSet) empty() bool { return len(s.v4) == 0 && len(s.v6) == 0 }

// add takes a masked, normalized prefix.
func (s *ipSet) add(p netip.Prefix) {
	ip := p.Addr()
	if ip.Is4() {
		b := ip.As4()
		lo := binary.BigEndian.Uint32(b[:])
		hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
		s.v4 = append(s.v4, r4{lo, hi})
		return
	}
	lo := addr128(ip)
	host := 128 - p.Bits()
	hi := lo
	switch {
	case host >= 64:
		hi.lo = ^uint64(0)
		hi.hi |= uint64(1)<<(host-64) - 1
		if host == 128 {
			hi.hi = ^uint64(0)
		}
	default:
		hi.lo |= uint64(1)<<host - 1
	}
	s.v6 = append(s.v6, r6{lo, hi})
}

func (s *ipSet) build() {
	slices.SortFunc(s.v4, func(a, b r4) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	out4 := s.v4[:0]
	for _, r := range s.v4 {
		if n := len(out4); n > 0 && (out4[n-1].hi == ^uint32(0) || r.lo <= out4[n-1].hi+1) {
			if r.hi > out4[n-1].hi {
				out4[n-1].hi = r.hi
			}
			continue
		}
		out4 = append(out4, r)
	}
	s.v4 = slices.Clip(out4)
	slices.SortFunc(s.v6, func(a, b r6) int {
		switch {
		case a.lo.less(b.lo):
			return -1
		case b.lo.less(a.lo):
			return 1
		}
		return 0
	})
	out6 := s.v6[:0]
	for _, r := range s.v6 {
		if n := len(out6); n > 0 {
			next, ovf := out6[n-1].hi.inc()
			if ovf || !next.less(r.lo) {
				if out6[n-1].hi.less(r.hi) {
					out6[n-1].hi = r.hi
				}
				continue
			}
		}
		out6 = append(out6, r)
	}
	s.v6 = slices.Clip(out6)
}

// contains expects an unmapped address without zone.
func (s *ipSet) contains(ip netip.Addr) bool {
	if ip.Is4() {
		b := ip.As4()
		x := binary.BigEndian.Uint32(b[:])
		lo, hi := 0, len(s.v4)
		for lo < hi { // first index with v4[i].lo > x
			m := int(uint(lo+hi) >> 1)
			if s.v4[m].lo <= x {
				lo = m + 1
			} else {
				hi = m
			}
		}
		return lo > 0 && x <= s.v4[lo-1].hi
	}
	if !ip.Is6() {
		return false
	}
	x := addr128(ip)
	lo, hi := 0, len(s.v6)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if !x.less(s.v6[m].lo) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo > 0 && !s.v6[lo-1].hi.less(x)
}

// addRange adds an arbitrary inclusive range of one family (binary formats).
func (s *ipSet) addRange(lo, hi netip.Addr) bool {
	lo, hi = lo.Unmap(), hi.Unmap()
	if !lo.IsValid() || lo.Is4() != hi.Is4() || hi.Less(lo) {
		return false
	}
	if lo.Is4() {
		a, b := lo.As4(), hi.As4()
		s.v4 = append(s.v4, r4{binary.BigEndian.Uint32(a[:]), binary.BigEndian.Uint32(b[:])})
		return true
	}
	s.v6 = append(s.v6, r6{addr128(lo), addr128(hi)})
	return true
}
