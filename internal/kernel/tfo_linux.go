//go:build linux

package kernel

import (
	"context"
	"errors"
	"net"
	"syscall"
)

const (
	tfoSupported     = true
	sockTCPFastOpen  = 0x17 // TCP_FASTOPEN
	sockTCPFOConnect = 0x1e // TCP_FASTOPEN_CONNECT (Linux 4.11+)
	tfoListenBacklog = 256
)

func setListenerTFO(ln net.Listener, on bool) error {
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		return errors.New("not a TCP listener")
	}
	rc, e := tl.SyscallConn()
	if e != nil {
		return e
	}
	q := 0
	if on {
		q = tfoListenBacklog
	}
	var se error
	if e := rc.Control(func(fd uintptr) { se = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, sockTCPFastOpen, q) }); e != nil {
		return e
	}
	return se
}

// tfoDialControl enables TCP_FASTOPEN_CONNECT; a kernel without it dials
// normally.
func tfoDialControl(_ context.Context, _, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, sockTCPFOConnect, 1) })
}
