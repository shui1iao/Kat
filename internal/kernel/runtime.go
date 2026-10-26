package kernel

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/api"
	"github.com/shui1iao/Kat/internal/stats"
)

// Version is reported by the management API; the CLI sets it.
var Version = "dev"

func (k *core) notice(lv logLevel, line string) {
	if k != nil && k.log != nil {
		_ = k.log.emit(lv, []byte(line+"\n"))
	}
}

// apiState is the running management interface and the options it runs with.
type apiState struct {
	mu   sync.Mutex
	srv  *api.Server
	opts api.Options
}

func (a *apiState) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	srv := a.srv
	a.srv = nil
	a.mu.Unlock()
	srv.Close()
}

func apiOptionsOf(c *Config) api.Options {
	if !c.apiEnabled() {
		return api.Options{}
	}
	return api.Options{Socket: c.API.Socket, Listen: c.API.Listen, Secret: c.API.Secret}
}

// startAPI starts the management interface when configured. Listener
// problems only warn: forwarding never depends on the API.
func (k *core) startAPI(c *Config) {
	if k.api == nil {
		k.api = &apiState{}
	}
	o := apiOptionsOf(c)
	if o.Socket == "" && o.Listen == "" {
		return
	}
	o.Debug = func(method, path string, status int) {
		if k.log.enabled(levelDebug) {
			k.notice(levelDebug, "kat event=api_request method="+eventToken(method, 8)+" path="+eventToken(path, 64)+" status="+strconv.Itoa(status))
		}
	}
	srv, errs := api.Start(o, apiBackend{k})
	k.api.mu.Lock()
	k.api.srv = srv
	k.api.mu.Unlock()
	for kind, e := range errs {
		reason := "listen_failed"
		switch {
		case errors.Is(e, api.ErrSocketInUse):
			reason = "socket_in_use"
		case errors.Is(e, api.ErrNotSocket):
			reason = "path_not_socket"
		case errors.Is(e, os.ErrPermission):
			reason = "permission_denied"
		}
		k.notice(levelWarn, "kat event=api_unavailable listener="+kind+" reason="+reason)
	}
	if _, bad := errs["unix"]; !bad && o.Socket != "" {
		k.notice(levelInfo, "kat event=api_ready unix="+eventToken(o.Socket, 256))
	}
	if _, bad := errs["tcp"]; !bad && o.Listen != "" {
		k.notice(levelInfo, "kat event=api_ready tcp="+eventToken(o.Listen, 64))
	}
}

// restartAPI applies changed api options after a reload. It runs on its own
// goroutine: the old interface finishes in-flight requests (including the
// reload request itself) before it is closed.
func (k *core) restartAPI(c *Config) {
	k.apiMu.Lock()
	defer k.apiMu.Unlock()
	k.mu.Lock()
	closing := k.closing
	k.mu.Unlock()
	if closing {
		return
	}
	k.api.close()
	k.startAPI(c)
}

// ---- management backend ----

type apiBackend struct{ k *core }

// StatsView is the JSON document of GET /v1/stats.
type StatsView struct {
	Version     string         `json:"version"`
	UptimeMS    int64          `json:"uptime_ms"`
	Rate        RateView       `json:"rate"`
	Connections ConnCounts     `json:"connections"`
	Persist     PersistView    `json:"persist"`
	Details     bool           `json:"details_enabled"`
	Cumulative  stats.Snapshot `json:"cumulative"`
	Providers   []ProviderView `json:"providers,omitempty"`
	Reload      ReloadView     `json:"reload"`
	Security    SecurityView   `json:"security"`
}

// RateView is the recent throughput in bytes per second.
type RateView struct {
	Up       float64 `json:"up_bytes_per_sec"`
	Down     float64 `json:"down_bytes_per_sec"`
	WindowMS int64   `json:"window_ms"`
}

// ConnCounts are the current counts: proxied TCP connections, UDP
// associations and accepted inbound transport connections; Rejected counts
// inbound connections refused by the connection/handshake budgets since start.
type ConnCounts struct {
	TCP      int64 `json:"tcp"`
	UDP      int64 `json:"udp"`
	Accepted int64 `json:"accepted"`
	Rejected int64 `json:"rejected_since_start"`
}

// PersistView reports the persistence state.
type PersistView struct {
	File       string    `json:"file,omitempty"`
	Enabled    bool      `json:"enabled"`
	LastSave   time.Time `json:"last_save,omitzero"`
	SaveErrors int64     `json:"save_errors"`
}

func (s *Server) StatsView() StatsView { return s.core.statsView() }

func (s *core) statsView() StatsView {
	up, down, w := s.reg.Rate()
	path := s.persistedPath()
	v := StatsView{Version: Version, UptimeMS: time.Since(s.started).Milliseconds(), Rate: RateView{up, down, w.Milliseconds()},
		Connections: ConnCounts{TCP: s.tcpFlows.Load(), UDP: s.counters.UDP.Load(), Accepted: s.counters.Active.Load(), Rejected: s.counters.Rejected.Load()},
		Persist:     PersistView{File: path, Enabled: path != "", SaveErrors: s.saveErrors.Load()},
		Details:     s.detailsOn.Load(), Cumulative: s.reg.Snapshot(), Reload: s.reloadView(), Security: s.securityView(), Providers: s.providerViews()}
	if t := s.lastSave.Load(); t != 0 {
		v.Persist.LastSave = time.Unix(0, t)
	}
	return v
}

func (b apiBackend) Version() string { return Version }
func (b apiBackend) Stats() any      { return b.k.statsView() }
func (b apiBackend) ResetStats() error {
	b.k.reg.Reset(time.Now())
	b.k.notice(levelInfo, "kat event=stats_reset")
	return b.k.saveStats()
}
func (b apiBackend) Connections() (any, bool) {
	if !b.k.detailsOn.Load() {
		return nil, false
	}
	return b.k.connections(), true
}
func (b apiBackend) CloseConnection(id uint64) (bool, bool) {
	if !b.k.detailsOn.Load() {
		return false, false
	}
	ok := b.k.closeFlow(id)
	if ok {
		b.k.notice(levelInfo, "kat event=connection_closed_by_api id="+strconv.FormatUint(id, 10))
	}
	return ok, true
}
func (b apiBackend) CloseAllConnections() (int, bool) {
	if !b.k.detailsOn.Load() {
		return 0, false
	}
	n := b.k.closeAllFlows()
	b.k.notice(levelInfo, "kat event=connections_closed_by_api count="+strconv.Itoa(n))
	return n, true
}
func (b apiBackend) LogLevel() string { return b.k.log.getLevel().String() }
func (b apiBackend) SetLogLevel(level string) error {
	lv, ok := parseLevel(level)
	if !ok || level == "" {
		return fmt.Errorf("invalid level")
	}
	old := b.k.log.getLevel()
	b.k.log.setLevel(lv)
	// Always visible: the change itself is logged at the higher of both levels.
	line := "kat event=log_level_changed from=" + old.String() + " to=" + lv.String()
	_ = b.k.log.emit(max(old, lv), []byte(line+"\n"))
	return nil
}
func (b apiBackend) Reload() (any, error) {
	g := b.k.gen.Load()
	if g == nil {
		return nil, errors.New("not running")
	}
	r, e := g.Reload("api")
	if e != nil {
		var re *ReloadError
		if errors.As(e, &re) {
			return r, &api.Failure{Code: "reload_failed", Stage: re.Stage, Message: re.Err.Error()}
		}
		return r, e
	}
	return r, nil
}
func (b apiBackend) Bans() any { return b.k.guard.list() }
func (b apiBackend) RemoveBan(source string) (bool, error) {
	found, e := b.k.guard.remove(source)
	if e != nil {
		return false, &api.Failure{Code: "bad_source", Message: e.Error()}
	}
	return found, nil
}
func (b apiBackend) SelectGroups() any {
	g := b.k.gen.Load()
	if g == nil {
		return []SelectGroup{}
	}
	return g.SelectGroups()
}
func (b apiBackend) Select(name, member string) error {
	g := b.k.gen.Load()
	if g == nil {
		return errors.New("not running")
	}
	e := g.Select(name, member)
	var se *SelectError
	if errors.As(e, &se) {
		return &api.Failure{Code: se.Code, Message: se.Msg}
	}
	return e
}

// Info writes a CLI startup line (e.g. "listening ...") through the
// configured log sink at info level.
func (s *Server) Info(line string) {
	if s.log != nil {
		_ = s.log.emit(levelInfo, []byte(line))
	}
}

// FinalLine writes one line after Close (shutdown/stopped) to the configured
// sink, reopening it briefly; level is "info" or "warn".
func FinalLine(c *Config, level, line string) {
	lv, _ := parseLevel(level)
	l, e := newLogger(c.Log)
	if e != nil {
		WriteDiagnosticLine(line)
		return
	}
	defer l.shutdown()
	_ = l.emit(lv, []byte(line))
}
