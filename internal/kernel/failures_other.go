//go:build !linux

package kernel

import "os"

// Non-Linux builds retain a small synchronous stderr diagnostic; the bounded
// nonblocking journal/pipe guarantee is provided by the deployed Linux sink.
func diagnosticStderr() (func([]byte) error, func()) {
	return func(b []byte) error { _, e := os.Stderr.Write(b); return e }, func() {}
}
