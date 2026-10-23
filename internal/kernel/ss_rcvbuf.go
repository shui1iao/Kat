package kernel

import (
	"fmt"
	"sync/atomic"
)

// Explicit, opt-in SS2017 UDP receive buffer (0.5.18).
//
// The only accepted value is the actual (kernel read-back) size 1MiB. Unset/0
// keeps the old behavior exactly: no socket option call and no budget charge.
// The positive increment actual-before of every enabled listener is charged to
// one process-wide 8MiB extra socket budget shared by all Servers/listeners. The
// budget is extra socket receive allowance, not process memory.
const (
	ss2017RcvBufActual    = 1 << 20
	ssRcvBufProcessBudget = 8 << 20
)

var ssRcvBufUsed atomic.Int64

type ssRcvBufError struct{ msg string }

func (e *ssRcvBufError) Error() string { return "udp_rcvbuf_2017: " + e.msg }

var errSSRcvBufUnsupported = &ssRcvBufError{"unsupported on this platform"}

// reserveSSRcvBuf atomically takes n bytes or nothing; concurrent callers can
// never push the total above the hard process budget.
func reserveSSRcvBuf(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := ssRcvBufUsed.Load()
		if cur+n > ssRcvBufProcessBudget {
			return false
		}
		if ssRcvBufUsed.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}
func returnSSRcvBuf(n int64) {
	if n > 0 {
		ssRcvBufUsed.Add(-n)
	}
}

// applySS2017RcvBuf raises one socket to target using get/set (ordinary
// SO_RCVBUF only). It conservatively reserves target-before first, then settles
// to the read-back increment. A read-back below target is an explicit failure
// with the whole reservation returned only after discard (closing the socket) ran.
// A default already >= target is left untouched (never shrunk) and charges 0.
func applySS2017RcvBuf(target int, get func() (int, error), set func(int) error, discard func()) (before, actual int, charge int64, err error) {
	if before, err = get(); err != nil {
		return 0, 0, 0, &ssRcvBufError{"cannot read SO_RCVBUF: " + err.Error()}
	}
	if before >= target {
		return before, before, 0, nil
	}
	reserved := int64(target - before)
	if !reserveSSRcvBuf(reserved) {
		return before, before, 0, &ssRcvBufError{fmt.Sprintf("process extra socket budget %d bytes exhausted (in use %d, need %d)", ssRcvBufProcessBudget, ssRcvBufUsed.Load(), reserved)}
	}
	fail := func(e error) (int, int, int64, error) {
		discard()
		returnSSRcvBuf(reserved)
		return before, actual, 0, e
	}
	if e := set(target); e != nil {
		return fail(&ssRcvBufError{"cannot set SO_RCVBUF: " + e.Error()})
	}
	if actual, err = get(); err != nil {
		return fail(&ssRcvBufError{"cannot read back SO_RCVBUF: " + err.Error()})
	}
	if actual < target {
		return fail(&ssRcvBufError{fmt.Sprintf("kernel granted %d bytes, below required %d (net.core.rmem_max limit?); listener refused", actual, target)})
	}
	charge = int64(actual - before)
	if charge > reserved {
		if !reserveSSRcvBuf(charge - reserved) {
			return fail(&ssRcvBufError{fmt.Sprintf("read-back %d exceeds remaining process budget", actual)})
		}
	} else {
		returnSSRcvBuf(reserved - charge)
	}
	return before, actual, charge, nil
}

// SSUDPReceiveBuffer reports one explicitly enabled SS2017 UDP listener.
type SSUDPReceiveBuffer struct {
	Address string
	Default int
	Actual  int
	Charged int64
}

func (s *Server) SSUDPReceiveBuffers() []SSUDPReceiveBuffer {
	var out []SSUDPReceiveBuffer
	for _, u := range s.ssListeners {
		if u.rcvbufActual != 0 {
			out = append(out, SSUDPReceiveBuffer{u.socket.LocalAddr().String(), u.rcvbufBefore, u.rcvbufActual, u.rcvbufInitial})
		}
	}
	return out
}
