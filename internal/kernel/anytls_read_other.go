//go:build !linux

package kernel

import "net"

func newAnyTLSDownRead(src, target net.Conn) func([]byte) ([]byte, []byte, error) { return nil }
