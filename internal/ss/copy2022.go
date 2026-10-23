package ss

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Write2022To is used only by the SS2022 TCP upload relay. Each authenticated
// record is written immediately, never waiting for a following record. readSize
// is the unchanged relay buffer size: only records that would have required the
// resident buffer in Read allocate/retain it here. Small records borrow the
// existing workspaces and return them before the next blocking header read.
// Authentication, nonce advancement, sticky read errors and clearing mirror
// read2022; ordinary Read and every SS2017 path remain unchanged.
// Read ownership is held across target Write to prevent concurrent Close from
// clearing in-use plaintext. The caller must unblock/close the target before
// waiting for TCPConn.Close to finish.
func (c *TCPConn) Write2022To(w io.Writer, readSize int) (int64, error) {
	if c.reader.max != MaxChunk2022 {
		return 0, ErrFormat
	}
	c.rMu.Lock()
	defer c.rMu.Unlock()
	r := &c.reader
	var total int64
	fail := func(err error) (int64, error) {
		r.fail(err)
		if err == io.EOF {
			return total, nil
		}
		return total, err
	}
	for {
		var data, workspace, storage []byte
		if len(r.pending) > 0 {
			data, r.pending = r.pending, nil
		} else if r.off < r.end {
			data = r.resident[r.off:r.end]
			r.off, r.end = 0, 0
		} else {
			if r.err != nil {
				if r.err == io.EOF {
					return total, nil
				}
				return total, r.err
			}
			var header [18]byte
			if _, err := io.ReadFull(r.r, header[:]); err != nil {
				return fail(err)
			}
			length, err := openInPlace(r.aead, &r.nonce, header[:])
			if err != nil {
				clear(header[:])
				return fail(err)
			}
			n := int(binary.BigEndian.Uint16(length))
			clear(header[:])
			if n > r.max {
				return fail(fmt.Errorf("%w: chunk length %d exceeds %d", ErrFormat, n, r.max))
			}
			if n > readSize && n >= 1024 {
				if err = r.readResident(n); err != nil {
					return fail(err)
				}
				continue
			}
			if n >= 1024 {
				workspace = take2022Workspace(n + r.aead.Overhead())
				storage = workspace[:n+r.aead.Overhead()]
			} else {
				storage = make([]byte, n+r.aead.Overhead())
			}
			if _, err = io.ReadFull(r.r, storage); err == nil {
				data, err = openInPlace(r.aead, &r.nonce, storage)
			} else if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				if workspace != nil {
					release2022Workspace(workspace)
				} else {
					clear(storage)
				}
				return fail(err)
			}
		}
		var nw int
		var ew error
		if len(data) > 0 {
			nw, ew = w.Write(data)
			if nw < 0 || nw > len(data) {
				nw, ew = 0, io.ErrShortWrite
			}
			if nw != len(data) && ew == nil {
				ew = io.ErrShortWrite
			}
			total += int64(nw)
		}
		clear(data)
		if workspace != nil {
			release2022Workspace(workspace)
		} else {
			clear(storage)
		}
		if ew != nil {
			return total, ew
		}
	}
}
