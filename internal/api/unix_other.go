//go:build !linux

package api

import "net"

// Other platforms rely on the socket file mode (0600, set right after bind)
// and, on Windows, on the per-user default directory ACL.
func listenPrivateUnix(path string) (net.Listener, error) { return net.Listen("unix", path) }

func peerCheckListener(ln net.Listener) net.Listener { return ln }
