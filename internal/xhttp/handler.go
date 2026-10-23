package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"time"
)

func (s *Server) handle(w http.ResponseWriter, r *http.Request, h Handler) {
	// Never let HTTP/1 auto-drain an untrusted body before an early rejection.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(s.cfg.IOTimeout))
	s.mu.Lock()
	if s.stopped || s.requests >= s.cfg.MaxRequests {
		s.mu.Unlock()
		http.Error(w, "request capacity", 503)
		return
	}
	s.requests++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.requests--; s.notify(); s.mu.Unlock() }()
	if !equalHost(r.Host, s.cfg.Host) {
		http.NotFound(w, r)
		return
	}
	id, seq, e := s.meta(r)
	if e != nil {
		if e == ErrAssociation {
			http.NotFound(w, r)
		} else {
			httpError(w, e)
		}
		return
	}
	if r.Method == "OPTIONS" {
		if e := s.responseHeaders(w, false); e != nil {
			http.Error(w, "padding RNG", 500)
			return
		}
		w.WriteHeader(200)
		return
	}
	if r.ProtoMajor != 1 && r.ProtoMajor != 2 {
		http.Error(w, "HTTP version", 400)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	if r.Method == "GET" && seq != nil {
		http.Error(w, "GET payload placement unsupported", 400)
		return
	}
	one := id == ""
	if one && (r.Method != "POST" || seq != nil || (s.cfg.Mode != Auto && s.cfg.Mode != StreamOne)) {
		http.Error(w, "stream-one not allowed", 400)
		return
	}
	if !one && s.cfg.Mode == StreamOne {
		http.Error(w, "split session not allowed", 400)
		return
	}
	if one {
		var token [16]byte
		if _, e = rand.Read(token[:]); e != nil {
			httpError(w, e)
			return
		}
		id = "one-" + hex.EncodeToString(token[:])
	}
	ss, e := s.getSession(id, peerIP(r))
	if e != nil {
		httpError(w, e)
		return
	}
	if one {
		s.streamOne(w, r, ss, h)
		return
	}
	if r.Method == "GET" {
		s.download(w, r, ss, h)
		return
	}
	if seq != nil {
		if s.cfg.Mode != Auto && s.cfg.Mode != PacketUp {
			httpError(w, ErrProtocol)
			return
		}
		s.packet(w, r, ss, *seq)
		return
	}
	if s.cfg.Mode != Auto && s.cfg.Mode != StreamUp {
		httpError(w, ErrProtocol)
		return
	}
	s.upload(w, r, ss)
}
func (s *Server) packet(w http.ResponseWriter, r *http.Request, ss *session, seq uint64) {
	if r.ContentLength > int64(s.cfg.MaxPacketBytes) {
		w.Header().Set("Connection", "close")
		http.Error(w, "upload too large", 413)
		return
	}
	n := s.cfg.MaxPacketBytes + 1
	if r.ContentLength >= 0 {
		n = int(r.ContentLength)
	}
	p, e := ss.reserve(seq, n)
	if e != nil {
		httpError(w, e)
		return
	}
	defer ss.abortPending(p)
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(s.cfg.IOTimeout))
	// Reserve capacity before allocating; known lengths use an exact-size buffer.
	data := make([]byte, n)
	if r.ContentLength >= 0 {
		_, e = io.ReadFull(r.Body, data)
	} else {
		var count int
		count, e = io.ReadFull(r.Body, data)
		if e == io.EOF || e == io.ErrUnexpectedEOF {
			data = data[:count]
			e = nil
		}
	}
	if e != nil || len(data) > s.cfg.MaxPacketBytes {
		ss.close(ErrProtocol)
		http.Error(w, "truncated/oversized upload", 400)
		return
	}
	if e = ss.commit(seq, p, data); e != nil {
		httpError(w, e)
		return
	}
	_ = controller.SetReadDeadline(time.Time{})
	if e := s.responseHeaders(w, false); e != nil {
		http.Error(w, "padding RNG", 500)
		return
	}
	w.WriteHeader(200)
}
func (s *Server) upload(w http.ResponseWriter, r *http.Request, ss *session) {
	if r.ContentLength > s.cfg.MaxUploadBytes {
		w.Header().Set("Connection", "close")
		http.Error(w, "upload too large", 413)
		return
	}
	if e := ss.setMode(StreamUp); e != nil {
		httpError(w, e)
		return
	}
	ss.mu.Lock()
	if ss.up {
		ss.mu.Unlock()
		httpError(w, ErrAssociation)
		return
	}
	ss.up = true

	ss.last = time.Now()
	ss.notify()
	ss.mu.Unlock()
	ss.attachBody(r, w)
	defer ss.detachBody()
	controller := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		if e := controller.EnableFullDuplex(); e != nil {
			ss.close(e)
			httpError(w, e)
			return
		}
	}
	if e := s.responseHeaders(w, false); e != nil {
		http.Error(w, "padding RNG", 500)
		return
	}
	w.WriteHeader(200)
	if e := controller.Flush(); e != nil {
		ss.close(e)
		return
	}
	// Keep the upload response alive until EOF/session close. No fake framing or
	// metadata is inserted into the raw application request body.
	select {
	case <-ss.uploadDone:
	case <-r.Context().Done():
		ss.close(context.Cause(r.Context()))
	case <-ss.ctx.Done():
	}
}
func (s *Server) claimDown(ss *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed {
		return ErrClosed
	}
	if ss.down {
		return ErrAssociation
	}
	if s.handlers >= s.cfg.MaxHandlers {
		return ErrLimit
	}
	ss.down = true
	s.handlers++
	ss.last = time.Now()
	ss.notify()
	return nil
}
func (s *Server) runHandler(w http.ResponseWriter, r *http.Request, ss *session, h Handler) {
	defer func() { ss.close(ErrClosed); s.mu.Lock(); s.handlers--; s.notify(); s.mu.Unlock() }()
	controller := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		if e := controller.EnableFullDuplex(); e != nil {
			ss.close(e)
			return
		}
	}
	if e := s.responseHeaders(w, true); e != nil {
		http.Error(w, "padding RNG", 500)
		return
	}
	w.WriteHeader(200)
	if e := controller.Flush(); e != nil {
		ss.close(e)
		return
	}
	writer := &responseWriter{w: w, controller: controller, session: ss, timeout: s.cfg.IOTimeout}
	stream := &Stream{session: ss, writer: writer}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-r.Context().Done():
			ss.close(context.Cause(r.Context()))
		case <-stop:
		}
	}()
	ss.mu.Lock()
	mode := ss.mode
	ss.mu.Unlock()
	if mode == "" {
		mode = "split-pending"
		if s.cfg.Mode != Auto {
			mode = s.cfg.Mode
		}
	}
	_ = h(ss.ctx, stream, Metadata{SessionID: ss.id, Mode: mode, RemoteIP: ss.owner, HTTPMajor: r.ProtoMajor, RemoteAddr: r.RemoteAddr})
}
func (s *Server) download(w http.ResponseWriter, r *http.Request, ss *session, h Handler) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	if e := s.claimDown(ss); e != nil {
		httpError(w, e)
		return
	}
	s.runHandler(w, r, ss, h)
}
func (s *Server) streamOne(w http.ResponseWriter, r *http.Request, ss *session, h Handler) {
	if r.ContentLength > s.cfg.MaxUploadBytes {
		ss.close(ErrLimit)
		w.Header().Set("Connection", "close")
		http.Error(w, "upload too large", 413)
		return
	}
	if e := ss.setMode(StreamOne); e != nil {
		httpError(w, e)
		return
	}
	ss.mu.Lock()
	ss.up = true

	ss.mu.Unlock()
	ss.attachBody(r, w)
	defer ss.detachBody()
	if e := s.claimDown(ss); e != nil {
		ss.close(e)
		httpError(w, e)
		return
	}
	s.runHandler(w, r, ss, h)
}
