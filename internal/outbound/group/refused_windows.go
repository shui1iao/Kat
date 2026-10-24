//go:build windows

package group

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is WSAECONNREFUSED. On Windows a refused connect fails with
// this Winsock code, which errors.Is does not equate with syscall.ECONNREFUSED.
const wsaeconnrefused = syscall.Errno(10061)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeconnrefused)
}
