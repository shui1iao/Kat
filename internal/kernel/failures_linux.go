//go:build linux

package kernel

import "syscall"

// No worker/queue/timer. Preserve inherited fd2 flags and shared file offsets.
// A journal socket uses per-call MSG_DONTWAIT; pipes/terminals are independently
// reopened nonblocking. Records stay below PIPE_BUF. Full sinks drop, not retry.
func diagnosticStderr() (func([]byte) error, func()) {
	var st syscall.Stat_t
	if e := syscall.Fstat(2, &st); e != nil {
		return func([]byte) error { return e }, func() {}
	}
	var fd int
	var e error
	socket := st.Mode&syscall.S_IFMT == syscall.S_IFSOCK
	if socket || st.Mode&syscall.S_IFMT == syscall.S_IFREG {
		fd, e = syscall.Dup(2)
		if e == nil {
			syscall.CloseOnExec(fd)
		}
	} else {
		fd, e = syscall.Open("/proc/self/fd/2", syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	}
	if e != nil {
		return func([]byte) error { return e }, func() {}
	}
	return func(b []byte) error {
		if socket {
			_, e := syscall.SendmsgN(fd, b, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
			return e
		}
		_, e := syscall.Write(fd, b)
		return e
	}, func() { _ = syscall.Close(fd) }
}
