package ss

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// A bounded shared cache, not one maximum-size buffer retained per connection.
// Size includes the largest 2017 record, both tags/length and possible salt.
const recordWorkspaceBytes = MaxChunk2017 + 2 + 32 + 32
const recordWorkspaceSlots = 32

var recordWorkspaces = make(chan *[recordWorkspaceBytes]byte, recordWorkspaceSlots)

func takeRecordWorkspace() *[recordWorkspaceBytes]byte {
	select {
	case p := <-recordWorkspaces:
		return p
	default:
		return new([recordWorkspaceBytes]byte)
	}
}
func releaseRecordWorkspace(p *[recordWorkspaceBytes]byte) {
	clear(p[:])
	select {
	case recordWorkspaces <- p:
	default:
	}
}
func openInPlace(a cipher.AEAD, n *counter, b []byte) ([]byte, error) {
	if n.exhausted {
		return nil, ErrNonceExhausted
	}
	p, e := a.Open(b[:0], n.value[:], b, nil)
	if e != nil {
		return nil, ErrAuth
	}
	n.advance()
	return p, nil
}
func sealAppend(a cipher.AEAD, n *counter, dst, p []byte) ([]byte, error) {
	if n.exhausted {
		return nil, ErrNonceExhausted
	}
	out := a.Seal(dst, n.value[:], p, nil)
	n.advance()
	return out, nil
}
func (r *recordReader) read2017(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		var header [18]byte
		if _, e := io.ReadFull(r.r, header[:]); e != nil {
			r.err = e
			return 0, e
		}
		length, e := openInPlace(r.aead, &r.nonce, header[:])
		if e != nil {
			r.err = e
			return 0, e
		}
		n := int(binary.BigEndian.Uint16(length))
		clear(header[:])
		if n > r.max {
			r.err = fmt.Errorf("%w: chunk length %d exceeds %d", ErrFormat, n, r.max)
			return 0, r.err
		}
		var workspace *[recordWorkspaceBytes]byte
		var encrypted []byte
		// Small handshake/tail records need not borrow and clear a large workspace.
		if n >= 1024 {
			workspace = takeRecordWorkspace()
			encrypted = workspace[:n+r.aead.Overhead()]
		} else {
			encrypted = make([]byte, n+r.aead.Overhead())
		}
		if _, e = io.ReadFull(r.r, encrypted); e == nil {
			encrypted, e = openInPlace(r.aead, &r.nonce, encrypted)
		} else if e == io.EOF {
			e = io.ErrUnexpectedEOF
		}
		if e != nil {
			if workspace != nil {
				releaseRecordWorkspace(workspace)
			} else {
				clear(encrypted)
			}
			r.err = e
			return 0, e
		}
		if len(p) >= n {
			copied := copy(p, encrypted)
			if workspace != nil {
				releaseRecordWorkspace(workspace)
			} else {
				clear(encrypted)
			}
			if copied == 0 {
				continue
			}
			return copied, nil
		}
		// A caller parsing a target or using short reads owns the remainder privately;
		// no plaintext slice can alias a workspace subsequently borrowed by another user.
		r.pending = append([]byte(nil), encrypted...)
		if workspace != nil {
			releaseRecordWorkspace(workspace)
		} else {
			clear(encrypted)
		}
	}
	n := copy(p, r.pending)
	clear(r.pending[:n])
	r.pending = r.pending[n:]
	if len(r.pending) == 0 {
		r.pending = nil
	}
	return n, nil
}
func (c *TCPConn) write2017Record(p []byte) error {
	workspace := takeRecordWorkspace()
	defer releaseRecordWorkspace(workspace)
	binary.BigEndian.PutUint16(workspace[:2], uint16(len(p)))
	wire, e := sealAppend(c.writerAEAD, &c.writeNonce, workspace[:0], workspace[:2])
	if e != nil {
		return e
	}
	wire, e = sealAppend(c.writerAEAD, &c.writeNonce, wire, p)
	if e != nil {
		return e
	}
	// Exactly one writeAll per record, just as the original merged-wire path.
	return writeAll(c.transport, wire)
}
