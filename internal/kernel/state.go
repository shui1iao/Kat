package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/stats"
)

// ---- instance state files ----
//
// The statistics file and the select state file live in the same state
// directory and share one instance lock (<stats file>.lock):
//   <name>.stats.json   cumulative traffic (stats.persist)
//   <name>.select.json  runtime choices of select groups

// selectStatePath derives the select state file from the statistics file.
func selectStatePath(statsFile string) string {
	dir, base := filepath.Split(statsFile)
	switch {
	case strings.HasSuffix(base, ".stats.json"):
		base = strings.TrimSuffix(base, ".stats.json")
	case strings.HasSuffix(base, ".json"):
		base = strings.TrimSuffix(base, ".json")
	}
	return filepath.Join(dir, base+".select.json")
}

// openState takes the instance lock and loads the select state (before the
// first generation is prepared). Problems only warn.
func (k *core) openState(c *Config) {
	if c.Stats == nil || c.Stats.File == "" {
		return
	}
	path := c.Stats.File
	release, e := stats.Lock(path)
	switch {
	case errors.Is(e, stats.ErrLocked):
		k.notice(levelWarn, "kat event=stats_persist_disabled reason=file_in_use file="+eventToken(path, 256))
		return
	case e != nil:
		k.notice(levelWarn, "kat event=stats_persist_disabled reason=lock_failed file="+eventToken(path, 256))
		return
	}
	k.statsMu.Lock()
	k.statsRelease = release
	k.lockedFile = path
	k.selPath = selectStatePath(path)
	k.statsMu.Unlock()
	k.loadSelections()
}

// loadStats loads persisted counters into the (already keyed) registry.
func (k *core) loadStats(c *Config) {
	k.statsMu.Lock()
	defer k.statsMu.Unlock()
	if !c.persistStats() || k.lockedFile != c.Stats.File {
		return
	}
	path := c.Stats.File
	if e := k.reg.Load(path); errors.Is(e, stats.ErrCorrupt) {
		moved, _ := stats.QuarantineCorrupt(path, time.Now())
		k.notice(levelWarn, "kat event=stats_load_failed reason=corrupt action=start_from_zero moved_to="+eventToken(moved, 300))
		k.statsPath = path
	} else if e != nil {
		k.notice(levelWarn, "kat event=stats_persist_disabled reason=load_failed file="+eventToken(path, 256))
	} else {
		k.statsPath = path
	}
}

// switchState follows a reload that changed stats.file or stats.persist.
// Counters are kept in memory; they are saved to the new file, never loaded
// from it (that would count bytes twice).
func (k *core) switchState(c *Config) {
	want := ""
	if c.Stats != nil {
		want = c.Stats.File
	}
	k.statsMu.Lock()
	cur := k.lockedFile
	k.statsMu.Unlock()
	if want != cur {
		k.saveStats()
		k.saveSelections()
		k.statsMu.Lock()
		if k.statsRelease != nil {
			k.statsRelease()
		}
		k.statsRelease, k.lockedFile, k.selPath, k.statsPath = nil, "", "", ""
		k.statsMu.Unlock()
		if want != "" {
			release, e := stats.Lock(want)
			if e != nil {
				reason := "lock_failed"
				if errors.Is(e, stats.ErrLocked) {
					reason = "file_in_use"
				}
				k.notice(levelWarn, "kat event=stats_persist_disabled reason="+reason+" file="+eventToken(want, 256))
			} else {
				k.statsMu.Lock()
				k.statsRelease, k.lockedFile, k.selPath = release, want, selectStatePath(want)
				k.statsMu.Unlock()
				k.saveSelections()
			}
		}
	}
	k.statsMu.Lock()
	if c.persistStats() && k.lockedFile == want && want != "" {
		k.statsPath = want
	} else {
		k.statsPath = ""
	}
	k.statsMu.Unlock()
}

func (k *core) releaseStatsLock() {
	k.statsMu.Lock()
	defer k.statsMu.Unlock()
	if k.statsRelease != nil {
		k.statsRelease()
		k.statsRelease = nil
	}
}

// startStats loads persisted counters (when configured) and starts the rate
// sampler and periodic saver. Persistence problems only warn.
func (k *core) startStats(c *Config) {
	k.loadStats(c)
	k.saveInterval.Store(int64(c.statsSaveInterval()))
	k.bgStop, k.bgDone = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(k.bgDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		last := time.Now()
		k.reg.Sample(last)
		for {
			select {
			case <-k.bgStop:
				return
			case now := <-tick.C:
				k.reg.Sample(now)
				if now.Sub(last) >= time.Duration(k.saveInterval.Load()) {
					last = now
					k.saveStats()
				}
			}
		}
	}()
}

// saveStats persists the counters; failures warn and never affect forwarding.
func (k *core) saveStats() error {
	k.saveMu.Lock()
	defer k.saveMu.Unlock()
	k.statsMu.Lock()
	path := k.statsPath
	k.statsMu.Unlock()
	if path == "" {
		return nil
	}
	e := k.reg.Save(path, time.Now())
	k.lastSave.Store(time.Now().UnixNano())
	if e != nil {
		k.saveErrors.Add(1)
		k.notice(levelWarn, "kat event=stats_save_failed reason=io file="+eventToken(path, 256))
		return e
	}
	k.notice(levelDebug, "kat event=stats_saved")
	return nil
}

// stopStats stops the background loop, saves once more and releases the lock.
func (k *core) stopStats() {
	if k.bgStop == nil {
		k.releaseStatsLock()
		return
	}
	k.stopOnce.Do(func() {
		close(k.bgStop)
		<-k.bgDone
		k.saveStats()
		k.saveSelections()
		k.releaseStatsLock()
	})
}

func (k *core) persistedPath() string {
	k.statsMu.Lock()
	defer k.statsMu.Unlock()
	return k.statsPath
}

// ---- select groups ----

// selRecord is the runtime choice of one select group and the configured
// default it was made against. A changed configured default (or a removed
// member) makes the configuration win again.
type selRecord struct {
	Selected string `json:"selected"`
	Config   string `json:"config_default"`
}

type selFile struct {
	Version int                  `json:"version"`
	Groups  map[string]selRecord `json:"groups"`
}

const selFileVersion = 1

// configuredDefault is the member a select group starts with by configuration.
func configuredDefault(g GroupConfig) string {
	if g.Expanded {
		return g.ConfigDefault
	}
	if g.Selected != "" {
		return g.Selected
	}
	if len(g.Members) > 0 {
		return g.Members[0]
	}
	return ""
}

func (k *core) loadSelections() {
	k.statsMu.Lock()
	path := k.selPath
	k.statsMu.Unlock()
	if path == "" {
		return
	}
	f, e := os.Open(path)
	if errors.Is(e, os.ErrNotExist) {
		return
	}
	if e != nil {
		k.notice(levelWarn, "kat event=select_state_load_failed reason=read_failed action=use_config file="+eventToken(path, 256))
		return
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	f.Close()
	var v selFile
	ok := e == nil && len(b) <= 1<<20
	if ok {
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.DisallowUnknownFields()
		ok = d.Decode(&v) == nil && v.Version == selFileVersion && !d.More()
	}
	if !ok {
		moved, _ := stats.QuarantineCorrupt(path, time.Now())
		k.notice(levelWarn, "kat event=select_state_load_failed reason=corrupt action=use_config moved_to="+eventToken(moved, 300))
		return
	}
	k.selMu.Lock()
	for n, r := range v.Groups {
		k.selections[n] = r
	}
	k.selMu.Unlock()
}

func (k *core) saveSelections() error {
	k.statsMu.Lock()
	path := k.selPath
	k.statsMu.Unlock()
	if path == "" {
		return nil
	}
	k.selMu.Lock()
	v := selFile{Version: selFileVersion, Groups: map[string]selRecord{}}
	for n, r := range k.selections {
		v.Groups[n] = r
	}
	k.selMu.Unlock()
	b, _ := json.MarshalIndent(v, "", "  ")
	b = append(b, '\n')
	if e := writeFileAtomic(path, b); e != nil {
		k.notice(levelWarn, "kat event=select_state_save_failed reason=io file="+eventToken(path, 256))
		return e
	}
	return nil
}

func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	_, e = tmp.Write(b)
	if e == nil {
		e = tmp.Sync()
	}
	if c := tmp.Close(); e == nil {
		e = c
	}
	if e == nil {
		e = os.Chmod(name, 0o600)
	}
	if e == nil {
		e = os.Rename(name, path)
	}
	if e != nil {
		os.Remove(name)
	}
	return e
}

// applySelections applies the remembered runtime choices to the select
// groups of g (not yet installed) and returns the selection table that
// goes with g plus one log line per dropped record: records of removed
// groups, removed members or changed configured defaults are dropped (the
// configuration wins).
func (k *core) applySelections(g *Server) (map[string]selRecord, []string) {
	k.selMu.Lock()
	defer k.selMu.Unlock()
	next := map[string]selRecord{}
	var notes []string
	cfgs := map[string]GroupConfig{}
	for _, gc := range g.cfg.Groups {
		if gc.Type == group.TypeSelect {
			cfgs[gc.Name] = gc
		}
	}
	for name, r := range k.selections {
		gc, ok := cfgs[name]
		if !ok || r.Config != configuredDefault(gc) || !contains(gc.Members, r.Selected) {
			reason := "group_removed"
			if ok {
				reason = "default_changed"
				if r.Config == configuredDefault(gc) {
					reason = "member_removed"
				}
			}
			notes = append(notes, "kat event=select_restored_config group="+eventToken(name, 64)+" reason="+reason)
			continue
		}
		next[name] = r
		if sel := g.selector(name); sel != nil {
			_ = sel.Select(r.Selected)
		}
	}
	return next, notes
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// selector returns the select group name of g.
func (s *Server) selector(name string) group.Selector {
	if s.rt == nil {
		return nil
	}
	for _, gr := range s.rt.groups {
		if gr.Name() == name && gr.Type() == group.TypeSelect {
			if sel, ok := gr.(group.Selector); ok {
				return sel
			}
		}
	}
	return nil
}

// SelectGroup is one entry of GET /v1/select.
type SelectGroup struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	Current string   `json:"current"`
	Default string   `json:"config_default"`
	Source  string   `json:"source"` // "runtime" or "config"
}

// SelectGroups lists the select groups of the running configuration.
func (s *Server) SelectGroups() []SelectGroup {
	k := s.core
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	g := s.current()
	k.selMu.Lock()
	defer k.selMu.Unlock()
	out := []SelectGroup{}
	for _, gc := range g.cfg.Groups {
		if gc.Type != group.TypeSelect {
			continue
		}
		v := SelectGroup{Name: gc.Name, Members: append([]string(nil), gc.Members...), Default: configuredDefault(gc), Source: "config"}
		for _, gr := range g.rt.groups {
			if gr.Name() == gc.Name {
				v.Current = gr.Current()
			}
		}
		if _, ok := k.selections[gc.Name]; ok {
			v.Source = "runtime"
		}
		out = append(out, v)
	}
	return out
}

// SelectError reports why a select request was refused.
type SelectError struct {
	Code string // unknown_group | not_select | unknown_member
	Msg  string
}

func (e *SelectError) Error() string { return e.Msg }

// Select switches select group name to member for new connections and
// remembers the choice (persisted with the instance state).
func (s *Server) Select(name, member string) error {
	k := s.core
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	g := s.current()
	var gc *GroupConfig
	for i := range g.cfg.Groups {
		if g.cfg.Groups[i].Name == name {
			gc = &g.cfg.Groups[i]
		}
	}
	if gc == nil {
		return &SelectError{"unknown_group", fmt.Sprintf("no group named %q", name)}
	}
	sel := g.selector(name)
	if gc.Type != group.TypeSelect || sel == nil {
		return &SelectError{"not_select", fmt.Sprintf("group %q is a %s group, not select", name, gc.Type)}
	}
	if !contains(gc.Members, member) {
		return &SelectError{"unknown_member", fmt.Sprintf("%q is not a member of group %q", member, name)}
	}
	if e := sel.Select(member); e != nil {
		return &SelectError{"unknown_member", e.Error()}
	}
	k.selMu.Lock()
	k.selections[name] = selRecord{Selected: member, Config: configuredDefault(*gc)}
	k.selMu.Unlock()
	k.saveSelections()
	k.notice(levelInfo, "kat event=select_changed group="+eventToken(name, 64)+" member="+eventToken(member, 64))
	return nil
}
