package anytls

import (
	"testing"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Test-only hooks for the external test package (which may import the kernel).

func ExportCertFiles(t *testing.T) (certFile, keyFile, pin string) {
	c := newTestCert(t)
	return c.certFile, c.keyFile, c.pin
}

func ExportSessionsCreated(o outbound.Outbound) int64 { return o.(*Outbound).sessionsCreated.Load() }

func ExportConcurrentEcho(t *testing.T, o outbound.Outbound, dst outbound.Addr, k, size int) {
	concurrentEcho(t, o.(*Outbound), dst, k, size)
}

func ExportWaitIdle(t *testing.T, o outbound.Outbound, n int) { waitIdle(t, o.(*Outbound), n) }

var (
	ExportTCPEcho      = tcpEchoServer
	ExportUDPEcho      = udpEchoServer
	ExportEchoRT       = echoRoundTrip
	ExportUDPRT        = udpRoundTrip
	ExportPattern      = pattern
	ExportCtx          = ctxTimeout
	ExportBaseOptions  = baseOptions
	ExportNewCounting  = func() *countingDialer { return &countingDialer{} }
	ExportCountedDials = func(d *countingDialer) int64 { return d.n.Load() }
)
