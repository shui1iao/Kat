//go:build !linux

package kernel

import "net"

const ss2017RcvBufSupported = false

// The 1MiB actual target relies on Linux SO_RCVBUF read-back semantics.
func setSS2017RcvBuf(*net.UDPConn, int) (int, int, int64, error) {
	return 0, 0, 0, errSSRcvBufUnsupported
}
