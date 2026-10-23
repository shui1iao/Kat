//go:build linux

package kernel

import (
	"net"

	"golang.org/x/sys/unix"
)

const ss2017RcvBufSupported = true

// setSS2017RcvBuf uses ordinary SO_RCVBUF only (never SO_RCVBUFFORCE, no sysctl).
// Linux doubles the requested value and caps the request at net.core.rmem_max,
// so target/2 is requested and the getsockopt read-back is authoritative. On
// failure the socket is closed before any reservation is returned.
func setSS2017RcvBuf(c *net.UDPConn, target int) (before, actual int, charge int64, err error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, 0, 0, &ssRcvBufError{"no raw socket: " + e.Error()}
	}
	get := func() (v int, err error) {
		if e := raw.Control(func(fd uintptr) { v, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) }); e != nil {
			return 0, e
		}
		return v, err
	}
	set := func(want int) (err error) {
		if e := raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, want/2) }); e != nil {
			return e
		}
		return err
	}
	return applySS2017RcvBuf(target, get, set, func() { c.Close() })
}
