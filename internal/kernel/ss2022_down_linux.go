//go:build linux

package kernel

import (
	"syscall"
	"unsafe"
)

// socketReadable is FIONREAD (SIOCINQ) on a TCP socket: bytes queued for read.
func socketReadable(fd uintptr) int {
	var n int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, 0x541B, uintptr(unsafe.Pointer(&n))); e != 0 {
		return 0
	}
	return int(n)
}
