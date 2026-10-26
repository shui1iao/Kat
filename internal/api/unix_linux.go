//go:build linux

package api

import (
	"net"
	"os"
	"sync"
	"syscall"
)

var umaskMu sync.Mutex

// listenPrivateUnix binds with umask 0177 so the socket is never briefly
// accessible to other users before the explicit chmod 0600.
func listenPrivateUnix(path string) (net.Listener, error) {
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	ln, e := net.Listen("unix", path)
	syscall.Umask(old)
	umaskMu.Unlock()
	return ln, e
}

// peerListener additionally refuses peers whose SO_PEERCRED uid is neither
// root nor the server's effective uid (defence in depth for custom paths).
type peerListener struct {
	net.Listener
	uid uint32
}

func peerCheckListener(ln net.Listener) net.Listener {
	return &peerListener{ln, uint32(os.Geteuid())}
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if l.allowed(c) {
			return c, nil
		}
		c.Close()
	}
}

func (l *peerListener) allowed(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, e := uc.SyscallConn()
	if e != nil {
		return false
	}
	var cred *syscall.Ucred
	var ce error
	if e := raw.Control(func(fd uintptr) {
		cred, ce = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); e != nil || ce != nil || cred == nil {
		return false
	}
	return cred.Uid == 0 || cred.Uid == l.uid
}
