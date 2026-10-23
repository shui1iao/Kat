package ss

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

type copy2022CloseSignal struct {
	closed chan struct{}
	once   sync.Once
}

func (c *copy2022CloseSignal) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *copy2022CloseSignal) Write(p []byte) (int, error) { return len(p), nil }
func (c *copy2022CloseSignal) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }

type copy2022HoldingWriter struct {
	entered chan []byte
	release chan struct{}
}

func (w *copy2022HoldingWriter) Write(p []byte) (int, error) {
	w.entered <- p
	<-w.release
	return 0, io.ErrClosedPipe
}

// Close must not clear a resident record while a target Write still owns it.
// The relay therefore has to unblock the target BEFORE calling codec.Close;
// dropping rMu around Write would turn this into a plaintext race/corruption.
func TestCopy2022CloseWaitsForBlockedWriteOwnership(t *testing.T) {
	for _, method := range methods[3:] {
		t.Run(method, func(t *testing.T) {
			srv := server(t, method)
			wire, plain := residentWire(t, srv, []int{32734})
			tr := &copy2022CloseSignal{closed: make(chan struct{})}
			c := &TCPConn{server: srv, transport: tr, reader: *residentReader(t, srv, wire)}
			writer := &copy2022HoldingWriter{entered: make(chan []byte, 1), release: make(chan struct{})}
			copied := make(chan error, 1)
			closed := make(chan error, 1)
			go func() { _, err := c.Write2022To(writer, 16384); copied <- err }()
			data := <-writer.entered
			if !bytes.Equal(data, plain) {
				close(writer.release)
				<-copied
				t.Fatal("incorrect plaintext")
			}
			go func() { closed <- c.Close() }()
			<-tr.closed // Close has closed the client transport and is now taking rMu.
			premature := false
			select {
			case <-closed:
				premature = true
			case <-time.After(20 * time.Millisecond):
			}
			// The blocked writer keeps exclusive ownership until explicitly released.
			intact := bytes.Equal(data, plain)
			close(writer.release)
			if err := <-copied; err != io.ErrClosedPipe {
				t.Error(err)
			}
			if !premature {
				<-closed
			}
			if premature || !intact {
				t.Error("Close cleared/released resident plaintext during target Write")
			}
			if c.reader.resident != nil || !bytes.Equal(data, make([]byte, len(data))) {
				t.Fatal("buffer was not cleared and detached after writer completion")
			}
		})
	}
}
