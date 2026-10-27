package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

// Reload lock order: reloadMu -> saveMu -> statsMu / selMu (never held
// together). Reset and both savers take saveMu first. A candidate holds the
// old instance lock until commit, and owns the new lock until commit/abort.
type statePlan struct {
	k                         *core
	want, persist, selectPath string
	release                   func()
	changed                   bool
	files                     []*stateFile
	held                      bool
}

// stateFile is a bounded in-process rename undo record, not crash recovery.
// Preparing never replaces the destination. Existing regular files are linked
// privately so an error on a later rename can restore their exact inode.
type stateFile struct {
	path, temp, backup string
	before             os.FileInfo
	installed          bool
}

func prepareStateFile(path string, write func(string) error) (*stateFile, error) {
	f := &stateFile{path: path}
	fail := func(e error) (*stateFile, error) { f.cleanup(); return nil, e }
	fi, e := os.Lstat(path)
	if e == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("state target is not a regular file: %s", path)
		}
		if fi.Mode().Perm()&0222 == 0 {
			return nil, fmt.Errorf("state target is not writable: %s", path)
		}
		f.before = fi
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if d, e := os.Stat(dir); e != nil {
		return nil, e
	} else if d.Mode().Perm()&0222 == 0 || d.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("state directory is not writable: %s", dir)
	}
	tmp, e := os.CreateTemp(dir, ".kat-reload-*")
	if e != nil {
		return nil, e
	}
	f.temp = tmp.Name()
	if e = tmp.Close(); e != nil {
		return fail(e)
	}
	if e = write(f.temp); e != nil {
		return fail(e)
	}
	// Exercise write/fsync/chmod/rename in this directory without touching the
	// target. Target-specific rename errors are still handled before publication.
	ready := f.temp + ".ready"
	if e = os.Rename(f.temp, ready); e != nil {
		return fail(e)
	}
	f.temp = ready
	if f.before != nil {
		backup := f.temp + ".previous"
		if e = os.Link(path, backup); e != nil {
			return fail(e)
		}
		f.backup = backup
	}
	return f, nil
}
func (f *stateFile) cleanup() {
	if f.temp != "" {
		_ = os.Remove(f.temp)
	}
	if f.backup != "" {
		_ = os.Remove(f.backup)
	}
}
func (f *stateFile) install() error {
	fi, e := os.Lstat(f.path)
	if f.before == nil {
		if e == nil {
			return fmt.Errorf("state target appeared during reload: %s", f.path)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	} else if e != nil {
		return e
	} else if !os.SameFile(fi, f.before) {
		return fmt.Errorf("state target changed during reload: %s", f.path)
	}
	if e = os.Rename(f.temp, f.path); e != nil {
		return e
	}
	f.temp = ""
	f.installed = true
	return nil
}
func (f *stateFile) undo() error {
	if !f.installed {
		return nil
	}
	var e error
	if f.before != nil {
		e = os.Rename(f.backup, f.path)
	} else {
		e = os.Remove(f.path)
	}
	if e == nil {
		f.installed = false
	}
	return e
}

func (k *core) prepareState(c *Config, selections map[string]selRecord) (*statePlan, error) {
	k.saveMu.Lock()
	p := &statePlan{k: k, held: true}
	fail := func(e error) (*statePlan, error) { p.abort(); return nil, e }
	if c.Stats != nil {
		p.want = c.Stats.File
	}
	k.statsMu.Lock()
	cur, oldStats, oldSelect := k.lockedFile, k.statsPath, k.selPath
	k.statsMu.Unlock()
	// Clean aliases must not contend with the instance's own lock.
	same := p.want == cur
	if !same && p.want != "" && cur != "" {
		a, _ := filepath.Abs(p.want)
		b, _ := filepath.Abs(cur)
		same = a == b
	}
	p.changed = !same
	if p.changed && p.want != "" {
		if fi, e := os.Lstat(p.want + ".lock"); e == nil && !fi.Mode().IsRegular() {
			return fail(errors.New("state lock is not a regular file"))
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return fail(e)
		}
		release, e := stats.Lock(p.want)
		if e != nil {
			return fail(e)
		}
		p.release = release
	}
	if p.want != "" {
		p.selectPath = selectStatePath(p.want)
	}
	if c.persistStats() && p.want != "" {
		p.persist = p.want
	}
	// Unchanged persistence paths do not need a probe or rewrite. A failed
	// startup lock/load is retried when reload requests that resource again.
	needStats := p.persist != "" && (p.changed || p.persist != oldStats)
	k.selMu.Lock()
	selectionsChanged := !reflect.DeepEqual(selections, k.selections)
	k.selMu.Unlock()
	needSelect := p.selectPath != "" && (p.changed || p.selectPath != oldSelect || selectionsChanged)
	type request struct {
		path  string
		write func(string) error
	}
	var reqs []request
	save := func(path string) error { return k.reg.Save(path, time.Now()) }
	if p.changed && oldStats != "" {
		reqs = append(reqs, request{oldStats, save})
	}
	if needStats {
		reqs = append(reqs, request{p.persist, save})
	}
	if needSelect {
		b, e := json.MarshalIndent(selFile{Version: selFileVersion, Groups: selections}, "", "  ")
		if e != nil {
			return fail(e)
		}
		b = append(b, '\n')
		reqs = append(reqs, request{p.selectPath, func(path string) error { return writeFileAtomic(path, b) }})
	}
	// New destinations win if a path is deliberately reused in a rotation.
	seen := map[string]bool{}
	for i := len(reqs) - 1; i >= 0; i-- {
		r := reqs[i]
		key, _ := filepath.Abs(r.path)
		if seen[key] {
			continue
		}
		seen[key] = true
		f, e := prepareStateFile(r.path, r.write)
		if e != nil {
			return fail(e)
		}
		p.files = append(p.files, f)
	}
	return p, nil
}
func (p *statePlan) install() error {
	for _, f := range p.files {
		if e := f.install(); e != nil {
			var restore error
			for i := len(p.files) - 1; i >= 0; i-- {
				restore = errors.Join(restore, p.files[i].undo())
			}
			if restore != nil {
				return fmt.Errorf("state rename failed: %v; restore failed: %w", e, restore)
			}
			return e
		}
	}
	return nil
}
func (p *statePlan) abort() {
	if p == nil {
		return
	}
	for _, f := range p.files {
		if !f.installed {
			f.cleanup()
		}
	}
	if p.release != nil {
		p.release()
		p.release = nil
	}
	if p.held {
		p.held = false
		p.k.saveMu.Unlock()
	}
}
func (p *statePlan) commit() {
	k := p.k
	k.statsMu.Lock()
	oldRelease := k.statsRelease
	if p.changed {
		k.statsRelease = p.release
		p.release = nil
	}
	k.lockedFile, k.statsPath, k.selPath = p.want, p.persist, p.selectPath
	k.statsMu.Unlock()
	if p.changed && oldRelease != nil {
		oldRelease()
	}
	for _, f := range p.files {
		f.cleanup()
	}
	p.held = false
	k.saveMu.Unlock()
}
