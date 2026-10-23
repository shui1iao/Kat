package vtransport

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func hasToken(value, want string) bool {
	for _, v := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}
func (s *Server) upgrade(w http.ResponseWriter, r *http.Request, h Handler) {
	if !hasToken(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || (r.Header.Get("Sec-WebSocket-Key") != "" || r.Header.Get("Sec-WebSocket-Protocol") != "") {
		http.Error(w, "not an HTTPUpgrade request", 400)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	st := &Stream{ctx: ctx, cancel: cancel}
	if !s.admit(st) {
		cancel()
		http.Error(w, "stream capacity", 503)
		return
	}
	defer s.finish(st)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP/1 required", 400)
		return
	}
	conn, rw, e := hijacker.Hijack()
	if e != nil {
		return
	}
	original, _ := r.Context().Value(connKey{}).(net.Conn)
	defer s.releaseConn(original)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.HeaderTimeout))
	if _, e = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); e != nil {
		return
	}
	if e = rw.Flush(); e != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	// The hijacked reader can already contain VLESS bytes sent with the headers.
	// Never discard it or re-read only the socket.
	writer := &deadlineWriter{conn: conn, timeout: s.cfg.IOTimeout}
	var half func() error
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		half = cw.CloseWrite
	}
	if !st.install(rw.Reader, writer, conn.Close, conn.SetReadDeadline, writer.SetDeadline, half) {
		return
	}

	_ = h(ctx, st, Metadata{Kind: HTTPUpgrade, Path: r.URL.Path, Host: r.Host, RemoteAddr: r.RemoteAddr})
}

type deadlineWriter struct {
	conn     net.Conn
	timeout  time.Duration
	mu       sync.Mutex
	deadline time.Time
}

func (w *deadlineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	end := time.Now().Add(w.timeout)
	if !w.deadline.IsZero() && w.deadline.Before(end) {
		end = w.deadline
	}
	w.mu.Unlock()
	_ = w.conn.SetWriteDeadline(end)
	return w.conn.Write(p)
}

func (w *deadlineWriter) SetDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
	return w.conn.SetWriteDeadline(t)
}
