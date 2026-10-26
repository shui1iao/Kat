//go:build !linux

package kernel

import "net"

func trySS2022DownBatch(dst, src net.Conn, target *ss2022DownConn, small int) (bool, error) {
	return false, nil
}

func trySS2022DownBatchM(dst, src net.Conn, target *ss2022DownConn, small int, m meter) (bool, error) {
	return false, nil
}
