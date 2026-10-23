//go:build !linux

package kernel

import "net"

func trySS2022DownBatch(dst, src net.Conn, target *ss2022DownConn, small int) (bool, error) {
	return false, nil
}
