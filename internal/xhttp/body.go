package xhttp

import (
	"io"
	"net/http"
	"time"
)

// A ResponseController may not be used after its HTTP handler returns. The
// separate lease guards the upload body's controller across split handlers.
// Reads are counted without holding bodyMu over blocking I/O, so Close can wake
// them; detach forbids new reads and joins existing reads before handler return.
func (ss *session) attachBody(r *http.Request, w http.ResponseWriter) {
	ss.bodyMu.Lock()
	defer ss.bodyMu.Unlock()
	ss.mu.Lock()
	ss.body = r.Body
	ss.bodyRC = http.NewResponseController(w)
	ss.bodyAlive = true
	ss.notify()
	ss.mu.Unlock()
	_ = ss.bodyRC.SetReadDeadline(time.Time{})
}
func (ss *session) interruptBody() {
	ss.bodyMu.Lock()
	defer ss.bodyMu.Unlock()
	if ss.bodyAlive {
		_ = ss.bodyRC.SetReadDeadline(time.Now())
		_ = ss.body.Close()
	}
}
func (ss *session) detachBody() {
	ss.bodyMu.Lock()
	if ss.bodyAlive {
		ss.bodyAlive = false
		_ = ss.bodyRC.SetReadDeadline(time.Now())
		_ = ss.body.Close()
	}
	ss.mu.Lock()
	ss.body = nil
	ss.bodyRC = nil
	ss.notify()
	ss.mu.Unlock()
	ss.bodyMu.Unlock()
	ss.bodyWG.Wait()
}
func (ss *session) readBody(b []byte, deadline time.Time) (int, error, bool) {
	ss.bodyMu.Lock()
	if !ss.bodyAlive {
		ss.bodyMu.Unlock()
		return 0, nil, false
	}
	body, rc := ss.body, ss.bodyRC
	ss.bodyWG.Add(1)
	end := time.Now().Add(ss.server.cfg.IdleTimeout)
	if !deadline.IsZero() && deadline.Before(end) {
		end = deadline
	}
	_ = rc.SetReadDeadline(end)
	ss.bodyMu.Unlock()
	ss.mu.Lock()
	remaining := ss.server.cfg.MaxUploadBytes - ss.uploaded
	ss.mu.Unlock()
	if int64(len(b)) > remaining+1 {
		b = b[:int(remaining+1)]
	}
	n, e := body.Read(b)
	ss.bodyWG.Done()
	ss.mu.Lock()
	ss.uploaded += int64(n)
	if n > 0 {
		ss.last = time.Now()
	}
	over := ss.uploaded > ss.server.cfg.MaxUploadBytes
	if e == io.EOF {
		ss.inputEOF = true
		ss.notify()
	}
	ss.mu.Unlock()
	if over {
		ss.close(ErrLimit)
		return 0, ErrLimit, true
	}
	if e != nil {
		ss.uploadOnce.Do(func() { close(ss.uploadDone) })
		if e != io.EOF {
			ss.close(e)
		}
	}
	return n, e, true
}
