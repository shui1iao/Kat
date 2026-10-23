//go:build linux

package kernel

import (
	"io"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Only real TCP target reads with the unchanged activity wrapper are eligible.
// RawConn keeps normal netpoll/deadline/Close semantics. The callback borrows a
// wire lease only for a nonblocking read attempt and releases it BEFORE returning
// false (netpoll wait). Thus idle targets hold no lease or extra resident buffer.
// It never waits to fill a frame, and never changes the existing pool budget.
func newAnyTLSDownRead(src, target net.Conn) func([]byte) ([]byte, []byte, error) {
	tcp, ok := target.(*net.TCPConn)
	if !ok {
		return nil
	}
	var activity *activityStream
	if a, ok := src.(*activityStream); ok {
		if a.Conn != target {
			return nil
		}
		activity = a
	} else if src != target {
		return nil
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil
	}
	return func(small []byte) (data, lease []byte, err error) {
		var readErr error
		n := 0
		err = raw.Read(func(fd uintptr) bool {
			lease = leaseAnyTLSDown()
			data = small
			if lease != nil {
				data = lease[7 : 7+32768]
			}
			for {
				n, readErr = unix.Read(int(fd), data)
				if readErr == syscall.EINTR {
					continue
				}
				if readErr == syscall.EAGAIN || readErr == syscall.EWOULDBLOCK {
					if lease != nil {
						// EAGAIN read no bytes: this borrowed fully-cleared buffer
						// is still clean. Avoid a second full-cap clear on an empty poll.
						returnClearedAnyTLSDown(lease)
						lease = nil
					}
					data = nil
					n = 0
					return false
				}
				return true
			}
		})
		if err == nil {
			err = readErr
		}
		if n < 0 {
			n = 0
		}
		if n == 0 && err == nil {
			err = io.EOF
		}
		data = data[:n]
		if n > 0 && activity != nil {
			activity.last.Store(time.Now().UnixNano())
		}
		return
	}
}
