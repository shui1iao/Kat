//go:build !linux

package kernel

import (
	"context"
	"net"
	"syscall"
)

const tfoSupported = false

func setListenerTFO(net.Listener, bool) error { return nil }

func tfoDialControl(context.Context, string, string, syscall.RawConn) error { return nil }
