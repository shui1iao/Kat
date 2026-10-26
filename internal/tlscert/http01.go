package tlscert

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// httpResponder answers HTTP-01 challenges on one listening address. It is
// shared by every ACME manager using the same address and only listens while
// at least one authorization is in progress.
type httpResponder struct {
	addr  string
	refs  int
	ln    net.Listener
	srv   *http.Server
	mu    sync.RWMutex
	paths map[string]string // challenge path -> key authorization
}

var (
	respMu     sync.Mutex
	responders = map[string]*httpResponder{}
)

// acquireHTTP returns the responder for addr, starting it when needed.
func acquireHTTP(addr string) (*httpResponder, error) {
	respMu.Lock()
	defer respMu.Unlock()
	if r := responders[addr]; r != nil {
		r.refs++
		return r, nil
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return nil, e
	}
	r := &httpResponder{addr: addr, refs: 1, ln: ln, paths: map[string]string{}}
	r.srv = &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	go r.srv.Serve(ln)
	responders[addr] = r
	return r, nil
}

func (r *httpResponder) release() {
	respMu.Lock()
	r.refs--
	last := r.refs == 0
	if last {
		delete(responders, r.addr)
	}
	respMu.Unlock()
	if last {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = r.srv.Shutdown(ctx)
		cancel()
		r.srv.Close()
	}
}

func (r *httpResponder) set(path, body string) {
	r.mu.Lock()
	r.paths[path] = body
	r.mu.Unlock()
}

func (r *httpResponder) del(path string) {
	r.mu.Lock()
	delete(r.paths, path)
	r.mu.Unlock()
}

func (r *httpResponder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead || !strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
		http.NotFound(w, req)
		return
	}
	r.mu.RLock()
	body, ok := r.paths[req.URL.Path]
	r.mu.RUnlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(body))
}
