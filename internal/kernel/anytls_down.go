package kernel

import (
	"io"
	"net"
	"time"
)

// A PSH header is seven bytes. Keep each combined frame within 64KiB;
// Stream.Write still enforces MaxFrameData and all existing queue budgets.
// Since0.5.12 the ready callback reads at most32768 payload bytes.
// Keep the SAME16 lease slots, right-size backing allocations to that exact
// payload+header rather than clearing/charging an untouched extra32KiB tail.
const anyTLSDownBytes = 32768 + 7
const anyTLSDownLeases = 16

// Only a full small read with more bytes already on the target socket borrows
// a lease. Nothing waits for a lease or for a larger batch. Idle streams retain
// no lease; at most16*32775=524400 additional bytes (below old16*65528) are retained process-wide.
var anyTLSDownSlots = make(chan struct{}, anyTLSDownLeases)
var anyTLSDownFree = make(chan []byte, anyTLSDownLeases)

func leaseAnyTLSDown() []byte {
	select {
	case anyTLSDownSlots <- struct{}{}:
	default:
		return nil
	}
	select {
	case b := <-anyTLSDownFree:
		return b
	default:
		return make([]byte, anyTLSDownBytes)
	}
}

func releaseAnyTLSDown(b []byte) {
	clear(b[:cap(b)])
	returnClearedAnyTLSDown(b)
}

// Only the owned-wire codec callback may bypass a second clear: it guarantees
// full-capacity clearing BEFORE calling this, including reject/cancel/error.
func returnClearedAnyTLSDown(b []byte) {
	select {
	case anyTLSDownFree <- b[:anyTLSDownBytes]:
	default:
	}
	<-anyTLSDownSlots
}

// Only relayAnyTLS's target->stream worker calls this. Keep the old 16377-byte
// read view when the target has no additional queued data or leases run out.
// ss2022Ready is the existing read-only socket readiness predicate (unknown
// sockets and non-Linux platforms return zero); no SS path or state is changed.
func (s *Server) copyAnyTLSDown(dst, src, target net.Conn) error {
	return s.copyAnyTLSDownM(dst, src, target, meter{})
}

func (s *Server) copyAnyTLSDownM(dst, src, target net.Conn, m meter) error {
	owner := s.pool.get()
	defer s.pool.put(owner)
	small := owner[:min(len(owner), 16377)]
	readReady := newAnyTLSDownRead(src, target)
	for {
		var n int
		var er error
		var buf, lease []byte
		if readReady != nil {
			buf, lease, er = readReady(small)
		} else {
			// The current profile still spends time in two target reads per
			// coalesced PSH. A hot target already has the bytes: read directly
			// into its existing owned-wire lease, no preliminary small copy.
			if ready := ss2022Ready(target); ready > len(small) {
				if lease = leaseAnyTLSDown(); lease != nil {
					n, er = src.Read(lease[7:min(anyTLSDownBytes, 7+ready)])
					buf = lease[7 : 7+n]
				}
			}
			if lease == nil {
				n, er = src.Read(small)
				buf = small[:n]
			}
			if lease == nil && er == nil && n == len(small) {
				if ready := ss2022Ready(target); ready > 0 {
					if lease = leaseAnyTLSDown(); lease != nil {
						m := copy(lease[7:], buf)
						k, e := src.Read(lease[7+m : min(anyTLSDownBytes, 7+m+ready)])
						buf, er = lease[7:7+m+k], e
					}
				}
			}
		}
		if len(buf) > 0 {
			var nw int
			var ew error
			if lease != nil {
				nw, ew = writeAnyTLSDownLease(dst, lease[:7+len(buf)])
				lease = nil // ownership passed to the writer, also on timeout/error
			} else {
				nw, ew = dst.Write(buf)
			}
			if nw < 0 || nw > len(buf) || (nw != len(buf) && ew == nil) {
				ew = io.ErrShortWrite
			}
			if nw > 0 && nw <= len(buf) {
				m.add(nw)
			}
			if lease != nil {
				releaseAnyTLSDown(lease)
			}
			if ew != nil {
				return ew
			}
		} else if lease != nil {
			releaseAnyTLSDown(lease)
		}
		if er != nil {
			if er == io.EOF {
				return nil
			}
			return er
		}
	}
}

// This opt-in is reachable only from the AnyTLS target->stream worker. The
// existing bounded target-read allocation becomes the owned outbound wire,
// eliminating another allocation/copy without adding an idle cache or budget.
func writeAnyTLSDownLease(dst net.Conn, wire []byte) (int, error) {
	raw := dst
	activity, active := dst.(*activityStream)
	if active {
		raw = activity.Conn
	}
	if stream, ok := raw.(*anyStream); ok {
		n, err := stream.st.WriteOwnedFrame(wire, returnClearedAnyTLSDown)
		if active && n > 0 {
			activity.last.Store(time.Now().UnixNano())
		}
		return n, err
	}
	// Test/non-stream destinations retain ordinary io.CopyBuffer behavior.
	n, err := dst.Write(wire[7:])
	releaseAnyTLSDown(wire)
	return n, err
}
