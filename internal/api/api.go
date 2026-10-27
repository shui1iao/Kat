// Package api is Kat's own management interface: HTTP/1.1 + JSON served on a
// Unix socket (default) and optionally on a loopback TCP address protected by
// a Bearer secret. Routes are versioned under /v1 so that later commands
// (reload, group selection) can be added without changing existing ones.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Backend is implemented by the kernel server.
type Backend interface {
	Version() string
	Stats() any
	ResetStats() error
	// Connections returns the active connection details; ok is false when
	// details are disabled by configuration.
	Connections() (list any, ok bool)
	CloseConnection(id uint64) (found, ok bool)
	CloseAllConnections() (closed int, ok bool)
	LogLevel() string
	SetLogLevel(level string) error
	// Reload re-reads the configuration file and installs it. A *Failure
	// reports a refused configuration (the running one is unchanged).
	Reload() (result any, err error)
	// SelectGroups lists the select groups; Select switches one of them.
	SelectGroups() any
	Select(group, member string) error
	// Bans lists the sources banned after authentication failures;
	// RemoveBan lifts one (found is false when it was not banned).
	Bans() any
	RemoveBan(source string) (found bool, err error)
}

// Failure is a refused request with a stable error code.
type Failure struct {
	Code    string
	Stage   string
	Message string
}

func (f *Failure) Error() string { return f.Code + ": " + f.Message }

// Options configures the listeners. Socket and Listen may each be empty.
type Options struct {
	Socket string
	Listen string
	Secret string
	// Debug, when set, receives one line per request (method, path, status).
	Debug func(method, path string, status int)
}

// Server owns active endpoints and every asynchronously draining predecessor.
// A retained endpoint loads its handler for EACH request, not per connection.
type Server struct {
	mu        sync.Mutex
	endpoints []*endpoint
	draining  map[*endpoint]bool
	closed    bool
}
type handlerSlot struct{ h http.Handler }
type endpoint struct {
	key     string
	ln      net.Listener
	srv     *http.Server
	handler atomic.Pointer[handlerSlot]
	done    chan struct{}
}

var ErrSocketInUse = errors.New("api: socket path is served by another process")
var ErrNotSocket = errors.New("api: socket path exists and is not a socket")

// Prepared owns bound, but not yet accepting, candidate endpoints.
// It is used only by the kernel's serialized reload transaction.
type Prepared struct {
	owner              *Server
	endpoints, created []*endpoint
	handlers           map[*endpoint]http.Handler
	dirs               []string
}

func endpointKey(kind, address string) string {
	if kind == "unix" {
		address = filepath.Clean(address)
	} else if a, e := netip.ParseAddrPort(address); e == nil {
		address = netip.AddrPortFrom(a.Addr().Unmap(), a.Port()).String()
	}
	return kind + ":" + address
}

func newEndpoint(kind, address string, strict bool) (*endpoint, error) {
	var ln net.Listener
	var e error
	if kind == "unix" {
		if strict {
			// Unlike startup, a failed reload must not remove even a stale foreign socket.
			if fi, err := os.Lstat(address); err == nil {
				if fi.Mode()&os.ModeSocket == 0 {
					return nil, ErrNotSocket
				}
				return nil, ErrSocketInUse
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		ln, e = listenUnix(address)
	} else {
		ln, e = net.Listen("tcp", address)
	}
	if e != nil {
		return nil, e
	}
	ep := &endpoint{key: endpointKey(kind, address), ln: ln, done: make(chan struct{})}
	ep.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ep.handler.Load().h.ServeHTTP(w, r) }), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	return ep, nil
}
func (e *endpoint) start() { go func() { defer close(e.done); _ = e.srv.Serve(e.ln) }() }
func (e *endpoint) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e.srv.Shutdown(ctx) != nil {
		_ = e.srv.Close()
	}
	<-e.done
}

// Start retains the historical best-effort startup behavior.
func Start(o Options, b Backend) (*Server, map[string]error) {
	s := &Server{draining: map[*endpoint]bool{}}
	errs := map[string]error{}
	h := handler(b, o.Debug)
	for _, v := range []struct{ kind, address string }{{"unix", o.Socket}, {"tcp", o.Listen}} {
		if v.address == "" {
			continue
		}
		e, err := newEndpoint(v.kind, v.address, false)
		if err != nil {
			errs[v.kind] = err
			continue
		}
		eh := h
		if v.kind == "tcp" {
			eh = requireBearer(o.Secret, h)
		}
		e.handler.Store(&handlerSlot{eh})
		s.endpoints = append(s.endpoints, e)
		e.start()
	}
	return s, errs
}

// Prepare reuses stable listeners and binds every new one without serving.
// Any failure closes ALL candidates. The running handlers stay untouched.
func Prepare(o Options, b Backend, s *Server) (*Prepared, error) {
	if s == nil {
		s = &Server{draining: map[*endpoint]bool{}}
	}
	s.mu.Lock()
	oldEndpoints := append([]*endpoint(nil), s.endpoints...)
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, errors.New("api: server is closed")
	}
	p := &Prepared{owner: s, handlers: map[*endpoint]http.Handler{}}
	h := handler(b, o.Debug)
	for _, v := range []struct{ kind, address string }{{"unix", o.Socket}, {"tcp", o.Listen}} {
		if v.address == "" {
			continue
		}
		var ep *endpoint
		for _, old := range oldEndpoints {
			if old.key == endpointKey(v.kind, v.address) {
				ep = old
				break
			}
		}
		if ep == nil {
			if v.kind == "unix" {
				// Remember only absent parents; abort removes them only if still empty.
				for d := filepath.Dir(v.address); d != "." && d != "/"; d = filepath.Dir(d) {
					if _, err := os.Lstat(d); err == nil {
						break
					} else if !errors.Is(err, os.ErrNotExist) {
						break
					}
					p.dirs = append(p.dirs, d)
				}
			}
			var err error
			ep, err = newEndpoint(v.kind, v.address, true)
			if err != nil {
				p.Abort()
				return nil, fmt.Errorf("%s listener: %w", v.kind, err)
			}
			p.created = append(p.created, ep)
		}
		eh := h
		if v.kind == "tcp" {
			eh = requireBearer(o.Secret, h)
		}
		p.endpoints = append(p.endpoints, ep)
		p.handlers[ep] = eh
	}
	return p, nil
}
func (p *Prepared) Abort() {
	if p == nil {
		return
	}
	for _, e := range p.created {
		_ = e.ln.Close()
	}
	for _, d := range p.dirs {
		_ = os.Remove(d)
	}
	p.created = nil
	p.dirs = nil
}

// Commit cannot fail. Removed listeners close immediately; Shutdown must NOT
// run synchronously in the goroutine answering POST /v1/reload.
func (p *Prepared) Commit() *Server {
	s := p.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := map[*endpoint]bool{}
	for _, e := range p.endpoints {
		keep[e] = true
		e.handler.Store(&handlerSlot{p.handlers[e]})
	}
	for _, e := range s.endpoints {
		if !keep[e] {
			// A request already admitted may finish. A new request on an old keepalive
			// connection cannot retain the old secret or execute management actions.
			e.handler.Store(&handlerSlot{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeError(w, http.StatusServiceUnavailable, "api_retired", "management endpoint retired")
			})})
			_ = e.ln.Close()
			e.srv.SetKeepAlivesEnabled(false)
			s.draining[e] = true
			go func(e *endpoint) { e.shutdown(); s.mu.Lock(); delete(s.draining, e); s.mu.Unlock() }(e)
		}
	}
	s.endpoints = p.endpoints
	for _, e := range p.created {
		e.start()
	}
	p.created = nil
	p.dirs = nil
	return s
}
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.Addr, len(s.endpoints))
	for i, e := range s.endpoints {
		out[i] = e.ln.Addr()
	}
	return out
}
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	all := map[*endpoint]bool{}
	for _, e := range s.endpoints {
		all[e] = true
	}
	for e := range s.draining {
		all[e] = true
	}
	for e := range all {
		_ = e.ln.Close()
		e.srv.SetKeepAlivesEnabled(false)
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for e := range all {
		wg.Add(1)
		go func(e *endpoint) { defer wg.Done(); e.shutdown() }(e)
	}
	wg.Wait()
}

func listenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if _, e := os.Stat(dir); errors.Is(e, os.ErrNotExist) {
		if e := os.MkdirAll(dir, 0o700); e != nil {
			return nil, e
		}
	}
	if fi, e := os.Lstat(path); e == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, ErrNotSocket
		}
		if c, e := net.DialTimeout("unix", path, time.Second); e == nil {
			c.Close()
			return nil, ErrSocketInUse
		}
		if e := os.Remove(path); e != nil {
			return nil, e
		}
	}
	ln, e := listenPrivateUnix(path)
	if e != nil {
		return nil, e
	}
	if e := os.Chmod(path, 0o600); e != nil {
		ln.Close()
		return nil, e
	}
	// Disable net.UnixListener's unconditional unlink-on-close. Ownership is
	// checked by inode so a draining predecessor cannot remove its replacement.
	if u, ok := ln.(*net.UnixListener); ok {
		u.SetUnlinkOnClose(false)
	}
	fi, e := os.Lstat(path)
	if e != nil {
		ln.Close()
		return nil, e
	}
	return peerCheckListener(&ownedUnixListener{Listener: ln, path: path, info: fi}), nil
}

type ownedUnixListener struct {
	net.Listener
	path string
	info os.FileInfo
	once sync.Once
}

func (l *ownedUnixListener) Close() error {
	e := l.Listener.Close()
	l.once.Do(func() {
		if fi, err := os.Lstat(l.path); err == nil && os.SameFile(fi, l.info) {
			_ = os.Remove(l.path)
		}
	})
	return e
}

func requireBearer(secret string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(sum[:], want[:]) != 1 || !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kat"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or wrong Bearer secret")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

func handler(b Backend, debug func(string, string, int)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": b.Version()})
	})
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, b.Stats())
	})
	mux.HandleFunc("POST /v1/stats/reset", func(w http.ResponseWriter, r *http.Request) {
		if e := b.ResetStats(); e != nil {
			// Counters are reset; only the immediate save failed.
			writeJSON(w, http.StatusOK, map[string]any{"reset": true, "saved": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"reset": true, "saved": true})
	})
	mux.HandleFunc("GET /v1/connections", func(w http.ResponseWriter, r *http.Request) {
		list, ok := b.Connections()
		if !ok {
			detailsDisabled(w)
			return
		}
		writeJSON(w, http.StatusOK, list)
	})
	mux.HandleFunc("DELETE /v1/connections", func(w http.ResponseWriter, r *http.Request) {
		n, ok := b.CloseAllConnections()
		if !ok {
			detailsDisabled(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"closed": n})
	})
	mux.HandleFunc("DELETE /v1/connections/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, e := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if e != nil || id == 0 {
			writeError(w, http.StatusBadRequest, "bad_id", "connection id must be a positive integer")
			return
		}
		found, ok := b.CloseConnection(id)
		switch {
		case !ok:
			detailsDisabled(w)
		case !found:
			writeError(w, http.StatusNotFound, "not_found", "no active connection with this id")
		default:
			writeJSON(w, http.StatusOK, map[string]any{"closed": 1, "id": id})
		}
	})
	mux.HandleFunc("GET /v1/log/level", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"level": b.LogLevel()})
	})
	mux.HandleFunc("PUT /v1/log/level", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Level string `json:"level"`
		}
		d := json.NewDecoder(io.LimitReader(r.Body, 4096))
		d.DisallowUnknownFields()
		if e := d.Decode(&req); e != nil {
			writeError(w, http.StatusBadRequest, "bad_request", `body must be {"level":"debug|info|warn|error"}`)
			return
		}
		if e := b.SetLogLevel(req.Level); e != nil {
			writeError(w, http.StatusBadRequest, "bad_level", "level must be debug, info, warn or error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"level": b.LogLevel()})
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		res, e := b.Reload()
		var f *Failure
		switch {
		case errors.As(e, &f):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": f.Code, "stage": f.Stage, "message": f.Message})
		case e != nil:
			writeError(w, http.StatusInternalServerError, "reload_failed", e.Error())
		default:
			writeJSON(w, http.StatusOK, res)
		}
	})
	mux.HandleFunc("GET /v1/select", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, b.SelectGroups())
	})
	mux.HandleFunc("PUT /v1/select/{group}", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Member string `json:"member"`
		}
		d := json.NewDecoder(io.LimitReader(r.Body, 4096))
		d.DisallowUnknownFields()
		if e := d.Decode(&req); e != nil || req.Member == "" {
			writeError(w, http.StatusBadRequest, "bad_request", `body must be {"member":"NAME"}`)
			return
		}
		e := b.Select(r.PathValue("group"), req.Member)
		var f *Failure
		switch {
		case errors.As(e, &f):
			status := http.StatusBadRequest
			switch f.Code {
			case "unknown_group":
				status = http.StatusNotFound
			case "not_select":
				status = http.StatusConflict
			}
			writeError(w, status, f.Code, f.Message)
		case e != nil:
			writeError(w, http.StatusInternalServerError, "select_failed", e.Error())
		default:
			writeJSON(w, http.StatusOK, map[string]string{"group": r.PathValue("group"), "selected": req.Member})
		}
	})
	mux.HandleFunc("GET /v1/bans", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, b.Bans())
	})
	mux.HandleFunc("DELETE /v1/bans/{source...}", func(w http.ResponseWriter, r *http.Request) {
		found, e := b.RemoveBan(r.PathValue("source"))
		var f *Failure
		switch {
		case errors.As(e, &f):
			writeError(w, http.StatusBadRequest, f.Code, f.Message)
		case e != nil:
			writeError(w, http.StatusInternalServerError, "unban_failed", e.Error())
		case !found:
			writeError(w, http.StatusNotFound, "not_found", "source is not banned")
		default:
			writeJSON(w, http.StatusOK, map[string]any{"removed": 1, "source": r.PathValue("source")})
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "unknown endpoint")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(sw, r)
		if debug != nil {
			debug(r.Method, r.URL.Path, sw.status)
		}
	})
}

func detailsDisabled(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "details_disabled", "connection details are disabled; set stats.connections to true")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
