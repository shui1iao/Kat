package kernel

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

type anyTLSUpReadActivity struct {
	io.Writer
	last *atomic.Int64
}

func (w anyTLSUpReadActivity) Write(p []byte) (int, error) {
	// Match the original activityStream.Read timestamp BEFORE target Write.
	w.last.Store(time.Now().UnixNano())
	return w.Writer.Write(p)
}
func (s *Server) copyAnyTLSUp(dst, src net.Conn) error { return s.copyAnyTLSUpM(dst, src, meter{}) }

func (s *Server) copyAnyTLSUpM(dst, src net.Conn, m meter) error {
	raw := src
	var target io.Writer = dst
	if activity, ok := src.(*activityStream); ok {
		raw = activity.Conn
		target = anyTLSUpReadActivity{dst, activity.last}
	}
	if stream, ok := raw.(*anyStream); ok {
		_, err := stream.st.WriteTCPTo(m.writer(target))
		return err
	}
	return s.copyM(dst, src, m)
}
