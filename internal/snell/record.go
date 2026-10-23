package snell

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"time"

	"golang.org/x/crypto/argon2"
)

const MaxPayload = 16383

var ErrProtocol = errors.New("snell: invalid wire data")
var ErrLimit = errors.New("snell: resource limit")
var ErrState = errors.New("snell: invalid lifecycle state")

func aeadFor(psk, salt []byte) (cipher.AEAD, error) {
	k := argon2.IDKey(psk, salt, 3, 8, 1, 32)
	b, err := aes.NewCipher(k[:16])
	clear(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

type recordReader struct {
	src     io.Reader
	a       cipher.AEAD
	counter uint64
	zero    bool
}

func (r *recordReader) open(c []byte) ([]byte, error) {
	if r.counter == math.MaxUint64 {
		return nil, ErrLimit
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:8], r.counter)
	p, e := r.a.Open(c[:0], nonce[:], c, nil)
	if e == nil {
		r.counter++
	}
	return p, e
}
func (r *recordReader) next() ([]byte, error) {
	r.zero = false
	h := make([]byte, 23)
	if _, e := io.ReadFull(r.src, h); e != nil {
		return nil, e
	}
	h, e := r.open(h)
	if e != nil {
		return nil, e
	}
	if h[0] != 4 || h[1] != 0 || h[2] != 0 {
		return nil, ErrProtocol
	}
	pad, n := int(binary.BigEndian.Uint16(h[3:5])), int(binary.BigEndian.Uint16(h[5:7]))
	if pad > MaxPayload || n > MaxPayload || (n == 0 && pad != 0) {
		return nil, ErrProtocol
	}
	if n == 0 {
		r.zero = true
		return nil, io.EOF
	}
	// A single bounded allocation holds the unauthenticated padding and body.
	b := make([]byte, pad+n+16)
	if _, e = io.ReadFull(r.src, b); e != nil {
		return nil, e
	}
	for i := 0; i < min(pad, n+16); i += 2 {
		b[i], b[pad+i] = b[pad+i], b[i]
	}
	return r.open(b[pad:])
}

type recordWriter struct {
	dst        io.Writer
	psk        []byte
	a          cipher.AEAD
	counter    uint64
	salt       [16]byte
	started    bool
	padding    int
	limit      int
	last       time.Time
	batchLeft  int
	batchLimit int
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (w *recordWriter) init() error {
	if w.a != nil {
		return nil
	}
	if _, e := rand.Read(w.salt[:]); e != nil {
		return e
	}
	var x [1]byte
	if _, e := rand.Read(x[:]); e != nil {
		return e
	}
	w.padding = 256 + int(x[0])
	a, e := aeadFor(w.psk, w.salt[:])
	w.a = a
	return e
}
func (w *recordWriter) seal(p []byte) ([]byte, error) {
	if w.counter == math.MaxUint64 {
		return nil, ErrLimit
	}
	var n [12]byte
	binary.LittleEndian.PutUint64(n[:8], w.counter)
	w.counter++
	return w.a.Seal(nil, n[:], p, nil), nil
}
func (w *recordWriter) frame(p []byte) error {
	if len(p) > MaxPayload {
		return ErrLimit
	}
	if w.started && len(p) >= 1024 {
		return w.framePooled(p)
	}
	return w.frameUnpooled(p)
}

// Initial shaped padding, small controls and zero frames keep the original path.
func (w *recordWriter) frameUnpooled(p []byte) error {
	if len(p) > MaxPayload {
		return ErrLimit
	}
	if e := w.init(); e != nil {
		return e
	}
	pad := 0
	if !w.started && len(p) > 0 {
		pad = w.padding
	}
	h := []byte{4, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[3:5], uint16(pad))
	binary.BigEndian.PutUint16(h[5:7], uint16(len(p)))
	head, e := w.seal(h)
	if e != nil {
		return e
	}
	var out []byte
	if !w.started {
		out = append(out, w.salt[:]...)
	}
	out = append(out, head...)
	if len(p) > 0 {
		c, e := w.seal(p)
		if e != nil {
			return e
		}
		padding, e := shapedPadding(pad, c)
		if e != nil {
			return e
		}
		for i := 0; i < min(pad, len(c)); i += 2 {
			padding[i], c[i] = c[i], padding[i]
		}
		out = append(out, padding...)
		out = append(out, c...)
	}
	w.started = true
	return writeAll(w.dst, out)
}
func (w *recordWriter) ceiling(now time.Time) int {
	v := w.limit
	if !w.started {
		v = 1460 - 55 - w.padding
	} else if w.last.IsZero() || now.Sub(w.last) >= 31*time.Second {
		v = 1421
	}
	if v == 0 {
		v = 1421
	}
	w.limit = min(v+1421, MaxPayload)
	w.last = now
	return v
}
func (w *recordWriter) stream(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if e := w.init(); e != nil {
		return 0, e
	}
	sent := 0
	for len(p) > 0 {
		now := time.Now()
		if w.batchLeft == 0 || (!w.last.IsZero() && now.Sub(w.last) >= 31*time.Second) {
			w.batchLimit = w.ceiling(now)
			w.batchLeft = 192 * 1024
		}
		w.last = now
		n := min(len(p), w.batchLimit, w.batchLeft)
		if e := w.frame(p[:n]); e != nil {
			return sent, e
		}
		sent += n
		w.batchLeft -= n
		p = p[n:]
	}
	return sent, nil
}
func (w *recordWriter) packet(p []byte) error {
	if e := w.init(); e != nil {
		return e
	}
	// Datagram atomicity takes precedence over the optional stream sizing policy.
	if len(p) > MaxPayload {
		return ErrLimit
	}
	w.batchLeft = 0
	w.ceiling(time.Now())
	return w.frame(p)
}
func (w *recordWriter) end() error {
	if e := w.init(); e != nil {
		return e
	}
	w.batchLeft = 0
	w.ceiling(time.Now())
	return w.frame(nil)
}
