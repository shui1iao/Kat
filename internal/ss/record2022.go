package ss

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The 2022 cache is separate from 2017: only borrowed while doing record I/O,
// never attached to an idle TCPConn. Cache limits are not total RSS limits.
const record2022SmallBytes = 16384 + 2 + 32
const record2022LargeBytes = MaxChunk2022 + 2 + 32

var record2022Small = make(chan []byte, 16)
var record2022Large = make(chan []byte, 4)

func take2022Workspace(n int) []byte {
	pool := record2022Small
	size := record2022SmallBytes
	if n > size {
		pool = record2022Large
		size = record2022LargeBytes
	}
	select {
	case p := <-pool:
		return p
	default:
		return make([]byte, size)
	}
}
func release2022Workspace(p []byte) {
	clear(p[:cap(p)])
	var pool chan []byte
	switch cap(p) {
	case record2022SmallBytes:
		pool = record2022Small
	case record2022LargeBytes:
		pool = record2022Large
	default:
		return
	}
	select {
	case pool <- p[:cap(p)]:
	default:
	}
}

// residentBytes is the fixed capacity of the SS2022 resident receive buffer:
// one maximum record plus its AEAD tag.
const residentBytes = MaxChunk2022 + 16

func (r *recordReader) releaseResident() {
	if r.resident != nil {
		clear(r.resident[:cap(r.resident)])
	}
	r.resident = nil
	r.off, r.end = 0, 0
}

// fail records a sticky read error; the resident buffer is cleared and released.
func (r *recordReader) fail(e error) (int, error) {
	r.err = e
	r.releaseResident()
	return 0, e
}

// readResident reads and opens one record of n plaintext bytes into the
// resident buffer, in place. The caller has already authenticated the length.
func (r *recordReader) readResident(n int) error {
	if r.resident == nil {
		r.resident = make([]byte, residentBytes)
	}
	storage := r.resident[:n+r.aead.Overhead()]
	_, e := io.ReadFull(r.r, storage)
	if e == io.EOF {
		e = io.ErrUnexpectedEOF
	}
	if e != nil {
		return e
	}
	plaintext, e := openInPlace(r.aead, &r.nonce, storage)
	if e != nil {
		return e
	}
	clear(storage[len(plaintext):])
	r.off, r.end = 0, len(plaintext)
	return nil
}

func (r *recordReader) read2022(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 && r.off == r.end {
		if r.err != nil {
			return 0, r.err
		}
		var header [18]byte
		if _, e := io.ReadFull(r.r, header[:]); e != nil {
			return r.fail(e)
		}
		length, e := openInPlace(r.aead, &r.nonce, header[:])
		if e != nil {
			clear(header[:])
			return r.fail(e)
		}
		n := int(binary.BigEndian.Uint16(length))
		clear(header[:])
		if n > r.max {
			return r.fail(fmt.Errorf("%w: chunk length %d exceeds %d", ErrFormat, n, r.max))
		}
		if len(p) < n && n >= 1024 {
			// Short caller: the record stays in the resident buffer and is
			// copied to the caller exactly once, below.
			if e := r.readResident(n); e != nil {
				return r.fail(e)
			}
			continue
		}
		var workspace, storage []byte
		if n >= 1024 {
			workspace = take2022Workspace(n + r.aead.Overhead())
			storage = workspace[:n+r.aead.Overhead()]
		} else {
			storage = make([]byte, n+r.aead.Overhead())
		}
		var plaintext []byte
		if _, e = io.ReadFull(r.r, storage); e == nil {
			plaintext, e = openInPlace(r.aead, &r.nonce, storage)
		} else if e == io.EOF {
			e = io.ErrUnexpectedEOF
		}
		if e != nil {
			if workspace != nil {
				release2022Workspace(workspace)
			} else {
				clear(storage)
			}
			return r.fail(e)
		}
		if len(p) >= n {
			copied := copy(p, plaintext)
			if workspace != nil {
				release2022Workspace(workspace)
			} else {
				clear(storage)
			}
			if copied == 0 {
				continue
			}
			return copied, nil
		}
		// Short callers own an exact private remainder, not an alias into the pool.
		r.pending = append([]byte(nil), plaintext...)
		if workspace != nil {
			release2022Workspace(workspace)
		} else {
			clear(storage)
		}
	}
	if len(r.pending) == 0 {
		n := copy(p, r.resident[r.off:r.end])
		clear(r.resident[r.off : r.off+n])
		r.off += n
		if r.off == r.end {
			r.off, r.end = 0, 0
		}
		return n, nil
	}
	n := copy(p, r.pending)
	clear(r.pending[:n])
	r.pending = r.pending[n:]
	if len(r.pending) == 0 {
		r.pending = nil
	}
	return n, nil
}
func (c *TCPConn) write2022Record(p []byte) error {
	workspace := take2022Workspace(len(p) + 2 + 2*c.writerAEAD.Overhead())
	defer release2022Workspace(workspace)
	binary.BigEndian.PutUint16(workspace[:2], uint16(len(p)))
	wire, e := sealAppend(c.writerAEAD, &c.writeNonce, workspace[:0], workspace[:2])
	if e != nil {
		return e
	}
	wire, e = sealAppend(c.writerAEAD, &c.writeNonce, wire, p)
	if e != nil {
		return e
	}
	return writeAll(c.transport, wire)
}
