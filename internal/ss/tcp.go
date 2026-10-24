package ss

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

type counter struct {
	value     [12]byte
	exhausted bool
}

func (n *counter) advance() {
	for i := range n.value {
		n.value[i]++
		if n.value[i] != 0 {
			return
		}
	}
	n.exhausted = true
}
func seal(a cipher.AEAD, n *counter, p []byte) ([]byte, error) {
	if n.exhausted {
		return nil, ErrNonceExhausted
	}
	out := a.Seal(nil, n.value[:], p, nil)
	n.advance()
	return out, nil
}
func open(a cipher.AEAD, n *counter, p []byte) ([]byte, error) {
	if n.exhausted {
		return nil, ErrNonceExhausted
	}
	out, err := a.Open(nil, n.value[:], p, nil)
	if err != nil {
		return nil, ErrAuth
	}
	n.advance()
	return out, nil
}

type recordReader struct {
	r       io.Reader
	aead    cipher.AEAD
	nonce   counter
	max     int
	pending []byte
	err     error

	// SS2022 only: per-connection resident receive buffer for records larger
	// than the caller's buffer. Allocated on first need, capacity is exactly
	// one maximum record plus tag, decrypted in place; resident[off:end] is the
	// unread plaintext window. Consumed bytes are cleared immediately; the
	// buffer is cleared and released on any read error and on Close. It is
	// never shared and never returned to a pool.
	resident []byte
	off, end int
}

func (r *recordReader) Read(p []byte) (int, error) {
	if r.max == MaxChunk2022 {
		return r.read2022(p)
	}
	if r.max == MaxChunk2017 {
		return r.read2017(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		lengthCipher := make([]byte, 2+r.aead.Overhead())
		if _, err := io.ReadFull(r.r, lengthCipher); err != nil {
			r.err = err
			return 0, err
		}
		length, err := open(r.aead, &r.nonce, lengthCipher)
		if err != nil {
			r.err = err
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(length))
		if n > r.max {
			r.err = fmt.Errorf("%w: chunk length %d exceeds %d", ErrFormat, n, r.max)
			return 0, r.err
		}
		payloadCipher := make([]byte, n+r.aead.Overhead())
		if _, err = io.ReadFull(r.r, payloadCipher); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			} // A length was authenticated: payload/tag must follow.
			r.err = err
			return 0, err
		}
		r.pending, err = open(r.aead, &r.nonce, payloadCipher)
		if err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// HandshakeError leaves the transport OPEN. The caller must use a uniform
// rejection policy (e.g. TCP SO_LINGER=0 reset, or SHUT_WR then bounded drain),
// including for short SIP022 initial reads. Blind Close with unread bytes may
// reveal a length oracle. Deadlines and non-TCP rejection are transport policy.
type HandshakeError struct {
	Cause    error
	emptyEOF bool
}

// EmptyEOF reports only a zero-byte EOF during the initial Read. Authentication
// and SIP022 first-read rejection remain unchanged. Used for quiet diagnostics.
func (e *HandshakeError) EmptyEOF() bool { return e.emptyEOF }

func (e *HandshakeError) Error() string { return "ss: handshake: " + e.Cause.Error() }
func (e *HandshakeError) Unwrap() error { return e.Cause }

// TCPConn is an authenticated plaintext stream, not a net.Conn implementation.
// One reader and one writer may run concurrently; concurrent reads/writes are
// serialized independently. The wrapper never bypasses encryption. CloseWrite
// delegates only if supported, otherwise returns ErrHalfCloseUnsupported without
// closing either direction. Deadlines remain on the supplied transport.
type TCPConn struct {
	transport   io.ReadWriteCloser
	server      *Server
	target      Address
	requestSalt []byte
	reader      recordReader
	rMu, wMu    sync.Mutex
	writerAEAD  cipher.AEAD
	writeNonce  counter
	werr        error
}

func (c *TCPConn) Target() Address     { return c.target }
func (c *TCPConn) UserID() string      { return c.server.user }
func (c *TCPConn) RequestSalt() []byte { return append([]byte(nil), c.requestSalt...) }
func (c *TCPConn) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	return c.reader.Read(p)
}
func (c *TCPConn) Close() error {
	// Close the transport first so a Read blocked in the transport returns and
	// releases rMu; then clear and drop the resident receive buffer.
	err := c.transport.Close()
	c.rMu.Lock()
	c.reader.releaseResident()
	c.rMu.Unlock()
	return err
}
func (c *TCPConn) CloseWrite() error {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.werr != nil {
		return c.werr
	}
	cw, ok := c.transport.(interface{ CloseWrite() error })
	if !ok {
		return ErrHalfCloseUnsupported
	}
	err := cw.CloseWrite()
	c.werr = io.ErrClosedPipe
	return err
}

// Accept authenticates and parses the complete target, but does not wait for
// application payload or dial a target. It supports server-first protocols.
// For SIP022 the initial salt+fixed header MUST arrive in exactly one Read as
// required by SIP022 section 3.1.4. Later headers/records support fragmentation.
// No reader buffer survives by aliasing a caller-owned packet slice.
func (s *Server) Accept(rwc io.ReadWriteCloser) (conn *TCPConn, err error) {
	emptyEOF := false
	defer func() {
		if err != nil {
			err = &HandshakeError{Cause: err, emptyEOF: emptyEOF}
		}
	}()
	if rwc == nil {
		return nil, ErrFormat
	}
	c := &TCPConn{transport: rwc, server: s}
	max := MaxChunk2017
	if s.m.v2022 {
		max = MaxChunk2022
	}
	c.reader = recordReader{r: rwc, max: max}
	if s.m.v2022 {
		initial := make([]byte, s.m.keySize+11+16)
		n, e := rwc.Read(initial)
		emptyEOF = n == 0 && e == io.EOF
		if n != len(initial) {
			return nil, fmt.Errorf("%w: got %d of %d bytes", ErrInitialRead, n, len(initial))
		}
		if e != nil {
			return nil, e
		}
		c.requestSalt = append([]byte(nil), initial[:s.m.keySize]...)
		c.reader.aead, err = s.aead(c.requestSalt)
		if err != nil {
			return nil, err
		}
		fixed, e := open(c.reader.aead, &c.reader.nonce, initial[s.m.keySize:])
		if e != nil {
			return nil, e
		}
		if fixed[0] != 0 {
			return nil, ErrFormat
		}
		stamp := binary.BigEndian.Uint64(fixed[1:9])
		if e = checkTime(stamp, s.now()); e != nil {
			return nil, e
		}
		size := int(binary.BigEndian.Uint16(fixed[9:11]))
		if size < 7 {
			return nil, ErrFormat
		}
		encrypted := make([]byte, size+16)
		if _, e = io.ReadFull(rwc, encrypted); e != nil {
			return nil, e
		}
		variable, e := open(c.reader.aead, &c.reader.nonce, encrypted)
		if e != nil {
			return nil, e
		}
		target, consumed, e := ParseAddress(variable)
		if e != nil {
			return nil, e
		}
		if len(variable) < consumed+2 {
			return nil, ErrFormat
		}
		padding := int(binary.BigEndian.Uint16(variable[consumed : consumed+2]))
		start := consumed + 2 + padding
		if padding > 900 || start > len(variable) || (padding == 0 && start == len(variable)) {
			return nil, ErrFormat
		}
		// The entire variable header (address/padding included) is authenticated and
		// structurally checked before committing the exact incoming salt set.
		s.mu.Lock()
		now := s.now()
		e = checkTime(stamp, now)
		if e == nil {
			e = s.tcpSalts.admit(c.requestSalt, now)
		}
		s.mu.Unlock()
		if e != nil {
			return nil, e
		}
		c.target = target
		c.reader.pending = variable[start:]
	} else {
		salt := make([]byte, s.m.keySize)
		if _, err = io.ReadFull(rwc, salt); err != nil {
			return nil, err
		}
		c.requestSalt = salt
		c.reader.aead, err = s.aead(salt)
		if err != nil {
			return nil, err
		}
		c.target, err = readAddress(&c.reader)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		err = s.oldSalts.admit(salt, s.now())
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (s *Server) responseSalt() ([]byte, error) {
	for i := 0; i < 8; i++ {
		salt, err := s.randomBytes(s.m.keySize)
		if err != nil {
			return nil, err
		}
		if s.m.v2022 {
			return salt, nil
		}
		s.mu.Lock()
		err = s.oldSalts.admit(salt, s.now())
		s.mu.Unlock()
		if err == nil {
			return salt, nil
		}
		if !errors.Is(err, ErrReplay) {
			return nil, err
		}
	}
	return nil, ErrReplay
}

// Write is lazy: no response header is sent until nonempty payload is available.
// The first SIP022 response write contains salt+authenticated response header
// (including request salt)+first payload in the same underlying Write. Ordinary
// TCP records never exceed 0x3fff (2017) / 0xffff (2022). Errors poison the writer.
func (c *TCPConn) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), c.reader.max)
		data := p[:n]
		if c.server.m.v2022 && c.writerAEAD != nil && n >= 1024 {
			if err := c.write2022Record(data); err != nil {
				c.werr = err
				return total, err
			}
			total += n
			p = p[n:]
			continue
		}
		if !c.server.m.v2022 && c.writerAEAD != nil && n >= 1024 {
			if err := c.write2017Record(data); err != nil {
				c.werr = err
				return total, err
			}
			total += n
			p = p[n:]
			continue
		}
		var wire []byte
		var err error
		if c.writerAEAD == nil {
			var salt []byte
			salt, err = c.server.responseSalt()
			if err != nil {
				c.werr = err
				return total, err
			}
			c.writerAEAD, err = c.server.aead(salt)
			if err != nil {
				c.werr = err
				return total, err
			}
			wire = append(wire, salt...)
			if c.server.m.v2022 {
				now := c.server.now().Unix()
				if now < 0 {
					c.werr = ErrTimestamp
					return total, c.werr
				}
				header := []byte{1}
				header = binary.BigEndian.AppendUint64(header, uint64(now))
				header = append(header, c.requestSalt...)
				header = binary.BigEndian.AppendUint16(header, uint16(n))
				var encrypted []byte
				encrypted, err = seal(c.writerAEAD, &c.writeNonce, header)
				wire = append(wire, encrypted...)
			} else {
				var encrypted []byte
				encrypted, err = seal(c.writerAEAD, &c.writeNonce, []byte{byte(n >> 8), byte(n)})
				wire = append(wire, encrypted...)
			}
		} else {
			var encrypted []byte
			encrypted, err = seal(c.writerAEAD, &c.writeNonce, []byte{byte(n >> 8), byte(n)})
			wire = append(wire, encrypted...)
		}
		if err == nil {
			var encrypted []byte
			encrypted, err = seal(c.writerAEAD, &c.writeNonce, data)
			wire = append(wire, encrypted...)
		}
		if err == nil {
			err = writeAll(c.transport, wire)
		}
		if err != nil {
			c.werr = err
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
