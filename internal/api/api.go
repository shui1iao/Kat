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
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// Server is a running management interface.
type Server struct {
	servers []*http.Server
	lns     []net.Listener
	wg      sync.WaitGroup
	once    sync.Once
}

// ErrSocketInUse: another live process serves the socket path.
var ErrSocketInUse = errors.New("api: socket path is served by another process")

// ErrNotSocket: the socket path exists and is not a socket; it is never removed.
var ErrNotSocket = errors.New("api: socket path exists and is not a socket")

// Start opens the configured listeners. A listener that cannot be opened is
// reported in errs (by "unix"/"tcp") while the others still run.
func Start(o Options, b Backend) (*Server, map[string]error) {
	s := &Server{}
	errs := map[string]error{}
	h := handler(b, o.Debug)
	if o.Socket != "" {
		if ln, e := listenUnix(o.Socket); e != nil {
			errs["unix"] = e
		} else {
			s.serve(ln, h)
		}
	}
	if o.Listen != "" {
		if ln, e := net.Listen("tcp", o.Listen); e != nil {
			errs["tcp"] = e
		} else {
			s.serve(ln, requireBearer(o.Secret, h))
		}
	}
	return s, errs
}

// Addrs returns the listening addresses (for tests and logs).
func (s *Server) Addrs() []net.Addr {
	out := make([]net.Addr, len(s.lns))
	for i, l := range s.lns {
		out[i] = l.Addr()
	}
	return out
}

func (s *Server) serve(ln net.Listener, h http.Handler) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	s.servers = append(s.servers, srv)
	s.lns = append(s.lns, ln)
	s.wg.Add(1)
	go func() { defer s.wg.Done(); _ = srv.Serve(ln) }()
}

// Close stops all listeners (removing the socket file) and waits briefly for
// in-flight requests.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, srv := range s.servers {
			if srv.Shutdown(ctx) != nil {
				srv.Close()
			}
		}
		s.wg.Wait()
	})
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
	return peerCheckListener(ln), nil
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
