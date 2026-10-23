package kernel

import (
	"github.com/shui1iao/Kat/internal/ss"
	"io"
	"net"
	"syscall"
)

// ss2022DownConn marks the dialed target of an SS2022 TCP relay so that only
// the target->client (download) copy may coalesce already-arrived target bytes
// into one SS2022 record of up to ss.MaxChunk2022 payload bytes instead of
// 16384B relay-buffer-sized records. Reads, writes, deadlines and every other
// method pass through embedding; real target half-close is forwarded.
type ss2022DownConn struct{ net.Conn }

func (c *ss2022DownConn) CloseWrite() error { return closeWrite(c.Conn) }

// ss2022DownTarget wraps the dialed target only for SS2022 TCP relays.
// SS2017, every other protocol and all UDP paths keep what they were given.
func ss2022DownTarget(in Inbound, out net.Conn) net.Conn {
	if in.ssRuntime != nil && in.ssRuntime.v2022 {
		return &ss2022DownConn{out}
	}
	return out
}

// ss2022DownSource reports the SS2022 target behind a copy source, looking
// through the idle-activity wrapper only.
func ss2022DownSource(src net.Conn) (*ss2022DownConn, bool) {
	if a, ok := src.(*activityStream); ok {
		src = a.Conn
	}
	d, ok := src.(*ss2022DownConn)
	return d, ok
}

// Coalescing buffers are a process-wide bounded lease, never attached to an
// idle connection: a buffer is held only while already-arrived bytes are read
// and written as one record, then cleared and returned. When all leases are
// in use the copy falls back to the ordinary relay buffer, so the extra memory
// is at most ss2022DownLeases*ss2022DownLeaseBytes regardless of connection count.
const ss2022DownBytes = ss.MaxChunk2022

// Include both AEAD tags and length in each lease, while retaining LESS
// than the original16*65535 total allocation bound. One fewer lease means a
// saturated relay falls back sooner; there is still no waiting or per-conn cache.
const ss2022DownLeaseBytes = ss2022DownBytes + 34
const ss2022DownLeases = 15

var ss2022DownSlots = make(chan struct{}, ss2022DownLeases)
var ss2022DownFree = make(chan []byte, ss2022DownLeases)

func leaseSS2022Down() []byte {
	select {
	case ss2022DownSlots <- struct{}{}:
	default:
		return nil
	}
	select {
	case b := <-ss2022DownFree:
		return b
	default:
		return make([]byte, ss2022DownLeaseBytes)
	}
}

func releaseSS2022Down(b []byte) {
	clear(b[:cap(b)])
	select {
	case ss2022DownFree <- b[:ss2022DownLeaseBytes]:
	default:
	}
	<-ss2022DownSlots
}

// ss2022Ready returns the number of bytes already queued on the target socket
// (0 when unknown or not a kernel socket).
func ss2022Ready(c net.Conn) int {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0
	}
	raw, e := sc.SyscallConn()
	if e != nil {
		return 0
	}
	n := 0
	if raw.Control(func(fd uintptr) { n = socketReadable(fd) }) != nil {
		return 0
	}
	return max(n, 0)
}

// copySS2022Down has io.CopyBuffer semantics (EOF is success, short writes
// fail, data returned together with a read error is written first). A read
// that fills the relay buffer is extended, without blocking, with bytes the
// target socket already holds, and the result is written in one Write, so the
// SS2022 writer emits one record of up to ss.MaxChunk2022 payload bytes.
func (s *Server) copySS2022Down(dst, src net.Conn, target *ss2022DownConn) error {
	small := s.pool.get()
	defer s.pool.put(small)
	for {
		// Readv into the existing bounded leases and encrypt them in place.
		// Unlike the rejected read-first experiment this batches records AND
		// removes the second writer workspace/copy, without raising any cap.
		if used, er := trySS2022DownBatch(dst, src, target, len(small)); used {
			if er != nil {
				if er == io.EOF {
					return nil
				}
				return er
			}
			continue
		}
		n, er := src.Read(small)
		buf, lease := small[:n], []byte(nil)
		if er == nil && n == len(small) && n < ss2022DownBytes {
			if ready := ss2022Ready(target.Conn); ready > 0 {
				if lease = leaseSS2022Down(); lease != nil {
					m := copy(lease, small[:n])
					k, e := src.Read(lease[m:min(ss2022DownBytes, m+ready)])
					buf, er = lease[:m+k], e
				}
			}
		}
		if len(buf) > 0 {
			nw, ew := dst.Write(buf)
			if nw < 0 || len(buf) < nw {
				nw, ew = 0, io.ErrShortWrite
			}
			if ew == nil && nw != len(buf) {
				ew = io.ErrShortWrite
			}
			if lease != nil {
				releaseSS2022Down(lease)
			}
			if ew != nil {
				return ew
			}
		} else if lease != nil {
			releaseSS2022Down(lease)
		}
		if er != nil {
			if er == io.EOF {
				return nil
			}
			return er
		}
	}
}
