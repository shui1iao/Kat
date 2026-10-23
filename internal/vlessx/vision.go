package vlessx

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
)

// Inner TLS recognition is incremental across Vision blocks and TCP fragments.
// It inspects bounded record/ServerHello syntax, never decrypts application TLS.
type tlsScan struct {
	buf, hand   []byte
	nonTLS, tls bool
	app         bool
}
type visionTLS struct {
	mu         sync.Mutex
	up, down   tlsScan
	tls13      bool
	seenServer bool
	cipher     uint16
}

func (s *visionTLS) feed(up bool, p []byte) (boundary, app, plain bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := &s.down
	if up {
		d = &s.up
	}
	if d.nonTLS {
		return true, false, true
	}
	for len(p) > 0 {
		need := 5 - len(d.buf)
		if len(d.buf) >= 5 {
			need = 5 + int(binary.BigEndian.Uint16(d.buf[3:5])) - len(d.buf)
		}
		n := min(len(p), need)
		d.buf = append(d.buf, p[:n]...)
		p = p[n:]
		if len(d.buf) < 5 {
			continue
		}
		kind := d.buf[0]
		size := int(binary.BigEndian.Uint16(d.buf[3:5]))
		if kind < 20 || kind > 23 || d.buf[1] != 3 || d.buf[2] > 4 || size > 18432 || size == 0 {
			d.nonTLS = true
			d.buf = nil
			d.hand = nil
			return true, false, true
		}
		if len(d.buf) < size+5 {
			continue
		}
		if kind == 22 {
			if len(d.hand)+size > 65536 {
				d.nonTLS = true
				d.buf = nil
				d.hand = nil
				return true, false, true
			}
			d.hand = append(d.hand, d.buf[5:]...)
			for len(d.hand) >= 4 {
				l := int(d.hand[1])<<16 | int(d.hand[2])<<8 | int(d.hand[3])
				if l > 65532 {
					d.nonTLS = true
					break
				}
				if len(d.hand) < l+4 {
					break
				}
				msg := d.hand[:l+4]
				if msg[0] == 1 && up && validClientHello(msg[4:]) {
					d.tls = true
				}
				if msg[0] == 2 && !up {
					d.tls = true
					s.seenServer = true
					s.tls13, s.cipher = parseServerHello(msg[4:])
				}
				d.hand = d.hand[l+4:]
			}
		}
		if kind == 23 {
			d.app = true
		}
		d.buf = nil
	}
	return len(d.buf) == 0, d.app, d.nonTLS
}
func validClientHello(b []byte) bool {
	if len(b) < 38 || b[0] != 3 || b[1] < 1 || b[1] > 3 {
		return false
	}
	n := int(b[34])
	if n > 32 || len(b) < 35+n+2 {
		return false
	}
	off := 35 + n
	l := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if l < 2 || l%2 != 0 || len(b) < off+l+1 {
		return false
	}
	off += l
	comp := int(b[off])
	off++
	if comp < 1 || len(b) < off+comp {
		return false
	}
	off += comp
	if len(b) == off {
		return true
	}
	if len(b) < off+2 {
		return false
	}
	return int(binary.BigEndian.Uint16(b[off:])) == len(b)-off-2
}
func parseServerHello(b []byte) (bool, uint16) {
	if len(b) < 38 || b[0] != 3 || b[1] != 3 {
		return false, 0
	}
	n := int(b[34])
	if n > 32 || len(b) < 35+n+5 {
		return false, 0
	}
	cipher := binary.BigEndian.Uint16(b[35+n:])
	off := 38 + n
	if len(b) < off+2 {
		return false, cipher
	}
	l := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if len(b) != off+l {
		return false, cipher
	}
	for off+4 <= len(b) {
		typ := binary.BigEndian.Uint16(b[off:])
		n := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+n > len(b) {
			return false, cipher
		}
		if typ == 43 && n == 2 && b[off] == 3 && b[off+1] == 4 {
			return cipher >= 0x1301 && cipher <= 0x1304, cipher
		}
		off += n
	}
	return false, cipher
}
func (s *visionTLS) canDirect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.up.tls && !s.up.nonTLS && !s.down.nonTLS && s.seenServer && s.tls13
}
func (s *visionTLS) isTLS() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.up.tls || s.down.tls }

// Vision implements the server side xtls-rprx-vision stream on RAW TLS1.3 or
// REALITY. Transport must have been created before handshake (recordGate).
// Response header must be sent BEFORE constructing/calling the Vision writer.
type Vision struct {
	transport                            *Transport
	uuid                                 [16]byte
	state                                visionTLS
	readMu, writeMu                      sync.Mutex
	firstRead, firstWrite                bool
	cache                                []byte
	readEnd, readRaw, writeEnd, writeRaw bool
	zeroBlocks                           int
}

func NewVision(t *Transport, id [16]byte) (*Vision, error) {
	if t == nil || t.TLSVersion() != 0x304 {
		return nil, ErrUnsupported
	}
	return &Vision{transport: t, uuid: id, firstRead: true, firstWrite: true}, nil
}
func (v *Vision) Read(p []byte) (int, error) {
	v.readMu.Lock()
	defer v.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(v.cache) == 0 {
		if v.readEnd {
			return v.transport.Read(p)
		}
		if v.firstRead {
			var id [16]byte
			if _, e := io.ReadFull(v.transport, id[:]); e != nil {
				return 0, e
			}
			if id != v.uuid {
				v.Close()
				return 0, ErrWire
			}
			v.firstRead = false
		}
		var h [5]byte
		if _, e := io.ReadFull(v.transport, h[:]); e != nil {
			return 0, e
		}
		cmd := h[0]
		n, pad := int(binary.BigEndian.Uint16(h[1:3])), int(binary.BigEndian.Uint16(h[3:5]))
		if cmd > 2 || n > 16384 || pad > 8192 {
			v.Close()
			return 0, ErrLimit
		}
		data := make([]byte, n)
		if _, e := io.ReadFull(v.transport, data); e != nil {
			v.Close()
			return 0, e
		}
		var discard [1024]byte
		for left := pad; left > 0; {
			k := min(left, len(discard))
			if _, e := io.ReadFull(v.transport, discard[:k]); e != nil {
				v.Close()
				return 0, e
			}
			left -= k
		}
		boundary, app, _ := v.state.feed(true, data)
		if n == 0 {
			v.zeroBlocks++
			if v.zeroBlocks > 64 {
				v.Close()
				return 0, ErrLimit
			}
		} else {
			v.zeroBlocks = 0
		}
		if cmd == 2 {
			if !v.state.canDirect() || !boundary || !app {
				v.Close()
				return 0, ErrWire
			}
			if e := v.transport.switchRead(); e != nil {
				v.Close()
				return 0, e
			}
			v.readRaw = true
			v.readEnd = true
		} else if cmd == 1 {
			v.readEnd = true
		}
		v.cache = data
	}
	n := copy(p, v.cache)
	v.cache = v.cache[n:]
	return n, nil
}
func (v *Vision) Write(p []byte) (int, error) {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if v.writeEnd {
		return v.transport.Write(p)
	}
	sent := 0
	for len(p) > 0 {
		n := min(len(p), 8192-21)
		data := p[:n]
		boundary, app, plain := v.state.feed(false, data)
		cmd := byte(0)
		if boundary && app {
			cmd = 1
			if v.state.canDirect() {
				cmd = 2
			}
		} else if plain {
			cmd = 1
		}
		var entropy [2]byte
		if _, e := rand.Read(entropy[:]); e != nil {
			return sent, e
		}
		pad := int(entropy[0])
		if v.state.isTLS() && n < 900 {
			pad = 900 - n + int(binary.BigEndian.Uint16(entropy[:])%500)
		}
		pad = min(pad, 8192-21-n)
		b := make([]byte, 0, 21+n+pad)
		if v.firstWrite {
			b = append(b, v.uuid[:]...)
			v.firstWrite = false
		}
		b = append(b, cmd, byte(n>>8), byte(n), byte(pad>>8), byte(pad))
		b = append(b, data...)
		b = append(b, make([]byte, pad)...)
		var e error
		if cmd == 2 {
			e = v.transport.writeFinalVision(b)
		} else {
			e = writeFull(v.transport, b)
		}
		if e != nil {
			v.Close()
			return sent, e
		}
		sent += n
		p = p[n:]
		if cmd != 0 {
			v.writeEnd = true
			if cmd == 2 {
				v.writeRaw = true
			}
			if len(p) > 0 {
				k, e := v.transport.Write(p)
				return sent + k, e
			}
			break
		}
	}
	return sent, nil
}
func (v *Vision) CloseWrite() error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	return v.transport.CloseWrite()
}
func (v *Vision) Close() error { return v.transport.Close() }

// DirectState reports protocol transitions for verification, not splice authority.
func (v *Vision) DirectState() (read, write bool) {
	v.readMu.Lock()
	defer v.readMu.Unlock()
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	return v.readRaw, v.writeRaw
}
