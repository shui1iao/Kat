package vtransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

func (s *Server) websocket(w http.ResponseWriter, r *http.Request, h Handler) {
	var early []byte
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if protocol != "" {
		if s.cfg.MaxEarlyData == 0 || strings.ContainsAny(protocol, ", \t\r\n") || len(protocol) > base64.RawURLEncoding.EncodedLen(s.cfg.MaxEarlyData) {
			http.Error(w, "unsupported early-data convention", 400)
			return
		}
		var e error
		early, e = base64.RawURLEncoding.Strict().DecodeString(protocol)
		if e != nil || len(early) == 0 || len(early) > s.cfg.MaxEarlyData {
			http.Error(w, "invalid early data", 400)
			return
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	st := &Stream{ctx: ctx, cancel: cancel}
	if !s.admit(st) {
		cancel()
		http.Error(w, "stream capacity", 503)
		return
	}
	defer s.finish(st)
	opts := &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled}
	if protocol != "" {
		opts.Subprotocols = []string{protocol}
	}
	ws, e := websocket.Accept(w, r, opts)
	if e != nil {
		return
	}
	defer ws.CloseNow()
	original, _ := r.Context().Value(connKey{}).(net.Conn)
	defer s.releaseConn(original)
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	// NetConn intentionally disables the websocket message limit; restore our
	// explicit budget AFTER constructing it, not before.
	ws.SetReadLimit(int64(s.cfg.MaxMessageBytes))
	writer := &wsWriter{conn: nc, timeout: s.cfg.IOTimeout, chunk: s.cfg.WriteChunkBytes}
	if !st.install(io.MultiReader(bytes.NewReader(early), nc), writer, ws.CloseNow, nc.SetReadDeadline, writer.SetDeadline, nil) {
		return
	}
	_ = h(ctx, st, Metadata{Kind: WebSocket, Path: r.URL.Path, Host: r.Host, EarlyDataBytes: len(early), RemoteAddr: r.RemoteAddr})
}

type wsWriter struct {
	conn     net.Conn
	timeout  time.Duration
	chunk    int
	mu       sync.Mutex
	deadline time.Time
}

func (w *wsWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), w.chunk)
		w.mu.Lock()
		end := time.Now().Add(w.timeout)
		if !w.deadline.IsZero() && w.deadline.Before(end) {
			end = w.deadline
		}
		w.mu.Unlock()
		_ = w.conn.SetWriteDeadline(end)
		sent, e := w.conn.Write(p[:n])
		total += sent
		if e != nil {
			return total, e
		}
		if sent != n {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

func (w *wsWriter) SetDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
	return w.conn.SetWriteDeadline(t)
}
