package snell

import (
	"encoding/binary"
	"math"
	"sync"
)

// Pooled records are already-started and thus have no salt/initial padding.
// Capacity is EXACTLY the final wire size, never a maximum buffer per writer.
const writeCacheFrames = 16
const writeCacheBytes = 256 * 1024

var writeBuffers struct {
	sync.Mutex
	frames [][]byte
	bytes  int
}

func takeWriteBuffer(n int) []byte {
	writeBuffers.Lock()
	for i, p := range writeBuffers.frames {
		if cap(p) == n {
			last := len(writeBuffers.frames) - 1
			writeBuffers.frames[i] = writeBuffers.frames[last]
			writeBuffers.frames[last] = nil
			writeBuffers.frames = writeBuffers.frames[:last]
			writeBuffers.bytes -= n
			writeBuffers.Unlock()
			return p[:n]
		}
	}
	writeBuffers.Unlock()
	return make([]byte, n)
}
func releaseWriteBuffer(p []byte) {
	p = p[:cap(p)]
	clear(p)
	writeBuffers.Lock()
	defer writeBuffers.Unlock()
	if len(writeBuffers.frames) < writeCacheFrames && writeBuffers.bytes+len(p) <= writeCacheBytes {
		writeBuffers.frames = append(writeBuffers.frames, p)
		writeBuffers.bytes += len(p)
	}
}
func (w *recordWriter) sealTo(dst, p []byte) ([]byte, error) {
	if w.counter == math.MaxUint64 {
		return nil, ErrLimit
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:8], w.counter)
	w.counter++
	return w.a.Seal(dst, nonce[:], p, nil), nil
}
func (w *recordWriter) framePooled(p []byte) error {
	if e := w.init(); e != nil {
		return e
	}
	owned := takeWriteBuffer(23 + len(p) + 16)
	// Only this invocation owns the buffer, including through partial/blocking I/O.
	// Close cannot return it; return occurs after writeAll completes or fails.
	defer releaseWriteBuffer(owned)
	clear(owned[:7])
	owned[0] = 4
	binary.BigEndian.PutUint16(owned[5:7], uint16(len(p)))
	wire, e := w.sealTo(owned[:0], owned[:7])
	if e != nil {
		return e
	}
	wire, e = w.sealTo(wire, p)
	if e != nil {
		return e
	}
	w.started = true
	return writeAll(w.dst, wire)
}
