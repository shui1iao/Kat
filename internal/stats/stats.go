// Package stats keeps Kat's cumulative traffic counters. Byte counts are the
// proxied payload (application bytes between the client and the target),
// never protocol framing. Counters are keyed by name so that persisted values
// survive restarts (and later reloads) independently of configuration order.
package stats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is one up/down byte pair. Up = client to target, Down = target to client.
type Counter struct {
	up, down atomic.Uint64
}

func (c *Counter) AddUp(n uint64)   { c.up.Add(n) }
func (c *Counter) AddDown(n uint64) { c.down.Add(n) }
func (c *Counter) Load() Traffic    { return Traffic{Up: c.up.Load(), Down: c.down.Load()} }
func (c *Counter) reset()           { c.up.Store(0); c.down.Store(0) }
func (c *Counter) add(t Traffic)    { c.up.Add(t.Up); c.down.Add(t.Down) }

// RuleCounter adds a hit count (connections / UDP targets decided by the rule).
type RuleCounter struct {
	Counter
	hits atomic.Uint64
}

func (r *RuleCounter) Hit() { r.hits.Add(1) }

// Traffic is a serializable byte pair.
type Traffic struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// RuleTraffic is a serializable rule counter.
type RuleTraffic struct {
	Hits uint64 `json:"hits"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// Named is one entry of an ordered snapshot list.
type Named struct {
	Name string `json:"name"`
	Traffic
}

// NamedRule is one rule entry of an ordered snapshot list.
type NamedRule struct {
	Name string `json:"name"`
	RuleTraffic
}

// Registry owns every cumulative counter of one server. The visible key set
// follows the configuration: Rekey (configuration reload) switches it to the
// keys of the new configuration while counters are kept by name, so totals of
// names present before and after continue. Counters of names that disappear
// stay in memory (connections may still add to them, and they resume if the
// name comes back) but are no longer reported or persisted. Lookups are
// lock-free reads of an immutable key set.
type Registry struct {
	Total Counter
	keys  atomic.Pointer[keyset]
	keyMu sync.Mutex   // serializes Rekey
	since atomic.Int64 // unix nanos: first start or last reset

	rateMu  sync.Mutex
	samples [rateSamples]sample
	next    int
	filled  int
}

type keyset struct {
	inbounds  map[string]*Counter
	outbounds map[string]*Counter
	groups    map[string]*Counter
	rules     map[string]*RuleCounter
	order     struct{ inbounds, outbounds, groups, rules []string }
}

const rateSamples = 6 // one per second: rate over the last five seconds

type sample struct {
	at       time.Time
	up, down uint64
}

func uniq(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := map[string]bool{}
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// New creates a registry with zeroed counters for the given keys.
func New(inbounds, outbounds, groups, rules []string, now time.Time) *Registry {
	r := &Registry{}
	r.keys.Store(&keyset{inbounds: map[string]*Counter{}, outbounds: map[string]*Counter{}, groups: map[string]*Counter{}, rules: map[string]*RuleCounter{}})
	r.Rekey(inbounds, outbounds, groups, rules)
	r.since.Store(now.UnixNano())
	return r
}

// Rekey makes the given keys the visible key set. Existing counters are kept
// by name; new names start at zero.
func (r *Registry) Rekey(inbounds, outbounds, groups, rules []string) {
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	old := r.keys.Load()
	k := &keyset{inbounds: map[string]*Counter{}, outbounds: map[string]*Counter{}, groups: map[string]*Counter{}, rules: map[string]*RuleCounter{}}
	for n, c := range old.inbounds {
		k.inbounds[n] = c
	}
	for n, c := range old.outbounds {
		k.outbounds[n] = c
	}
	for n, c := range old.groups {
		k.groups[n] = c
	}
	for n, c := range old.rules {
		k.rules[n] = c
	}
	k.order.inbounds, k.order.outbounds, k.order.groups, k.order.rules = uniq(inbounds), uniq(outbounds), uniq(groups), uniq(rules)
	for _, n := range k.order.inbounds {
		if k.inbounds[n] == nil {
			k.inbounds[n] = &Counter{}
		}
	}
	for _, n := range k.order.outbounds {
		if k.outbounds[n] == nil {
			k.outbounds[n] = &Counter{}
		}
	}
	for _, n := range k.order.groups {
		if k.groups[n] == nil {
			k.groups[n] = &Counter{}
		}
	}
	for _, n := range k.order.rules {
		if k.rules[n] == nil {
			k.rules[n] = &RuleCounter{}
		}
	}
	r.keys.Store(k)
}

func (r *Registry) Inbound(k string) *Counter  { return r.keys.Load().inbounds[k] }
func (r *Registry) Outbound(k string) *Counter { return r.keys.Load().outbounds[k] }
func (r *Registry) Group(k string) *Counter    { return r.keys.Load().groups[k] }
func (r *Registry) Rule(k string) *RuleCounter { return r.keys.Load().rules[k] }

// Snapshot is the cumulative view returned by the management API.
type Snapshot struct {
	Since     time.Time   `json:"since"`
	Total     Traffic     `json:"total"`
	Inbounds  []Named     `json:"inbounds"`
	Outbounds []Named     `json:"outbounds"`
	Groups    []Named     `json:"groups"`
	Rules     []NamedRule `json:"rules"`
}

func (r *Registry) Snapshot() Snapshot {
	s := Snapshot{Since: time.Unix(0, r.since.Load()), Total: r.Total.Load(), Inbounds: []Named{}, Outbounds: []Named{}, Groups: []Named{}, Rules: []NamedRule{}}
	ks := r.keys.Load()
	for _, k := range ks.order.inbounds {
		s.Inbounds = append(s.Inbounds, Named{k, ks.inbounds[k].Load()})
	}
	for _, k := range ks.order.outbounds {
		s.Outbounds = append(s.Outbounds, Named{k, ks.outbounds[k].Load()})
	}
	for _, k := range ks.order.groups {
		s.Groups = append(s.Groups, Named{k, ks.groups[k].Load()})
	}
	for _, k := range ks.order.rules {
		c := ks.rules[k]
		t := c.Load()
		s.Rules = append(s.Rules, NamedRule{k, RuleTraffic{Hits: c.hits.Load(), Up: t.Up, Down: t.Down}})
	}
	return s
}

// Reset zeroes every cumulative counter (not the per-connection counters).
func (r *Registry) Reset(now time.Time) {
	r.Total.reset()
	ks := r.keys.Load()
	for _, c := range ks.inbounds {
		c.reset()
	}
	for _, c := range ks.outbounds {
		c.reset()
	}
	for _, c := range ks.groups {
		c.reset()
	}
	for _, c := range ks.rules {
		c.reset()
		c.hits.Store(0)
	}
	r.since.Store(now.UnixNano())
	r.rateMu.Lock()
	r.filled, r.next = 0, 0
	r.rateMu.Unlock()
}

// Sample records the total counter for the rate window (call about once a second).
func (r *Registry) Sample(now time.Time) {
	t := r.Total.Load()
	r.rateMu.Lock()
	r.samples[r.next] = sample{now, t.Up, t.Down}
	r.next = (r.next + 1) % rateSamples
	if r.filled < rateSamples {
		r.filled++
	}
	r.rateMu.Unlock()
}

// Rate returns bytes per second over the sampled window (up to five seconds).
func (r *Registry) Rate() (up, down float64, window time.Duration) {
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	if r.filled < 2 {
		return 0, 0, 0
	}
	newest := r.samples[(r.next+rateSamples-1)%rateSamples]
	oldest := r.samples[(r.next+rateSamples-r.filled)%rateSamples]
	dt := newest.at.Sub(oldest.at)
	if dt <= 0 {
		return 0, 0, 0
	}
	sec := dt.Seconds()
	if newest.up >= oldest.up {
		up = float64(newest.up-oldest.up) / sec
	}
	if newest.down >= oldest.down {
		down = float64(newest.down-oldest.down) / sec
	}
	return up, down, dt
}

// ---- persistence ----

const fileVersion = 1

type file struct {
	Version   int                    `json:"version"`
	SavedAt   time.Time              `json:"saved_at"`
	Since     time.Time              `json:"since"`
	Total     Traffic                `json:"total"`
	Inbounds  map[string]Traffic     `json:"inbounds"`
	Outbounds map[string]Traffic     `json:"outbounds"`
	Groups    map[string]Traffic     `json:"groups"`
	Rules     map[string]RuleTraffic `json:"rules"`
}

// ErrCorrupt reports an unreadable or invalid statistics file.
var ErrCorrupt = errors.New("stats: corrupt statistics file")

const maxFileBytes = 16 << 20

// Load adds the persisted values to the (fresh) counters. A missing file is
// not an error. A corrupt file returns ErrCorrupt and leaves the counters at
// zero; the caller decides how to report it. Keys that no longer exist in
// the configuration are dropped.
func (r *Registry) Load(path string) error {
	f, e := os.Open(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if e != nil {
		return e
	}
	if len(b) > maxFileBytes {
		return ErrCorrupt
	}
	var v file
	d := json.NewDecoder(bytesReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil || v.Version != fileVersion {
		return ErrCorrupt
	}
	if d.More() {
		return ErrCorrupt
	}
	r.Total.add(v.Total)
	ks := r.keys.Load()
	for k, t := range v.Inbounds {
		if c := ks.inbounds[k]; c != nil {
			c.add(t)
		}
	}
	for k, t := range v.Outbounds {
		if c := ks.outbounds[k]; c != nil {
			c.add(t)
		}
	}
	for k, t := range v.Groups {
		if c := ks.groups[k]; c != nil {
			c.add(t)
		}
	}
	for k, t := range v.Rules {
		if c := ks.rules[k]; c != nil {
			c.add(Traffic{t.Up, t.Down})
			c.hits.Add(t.Hits)
		}
	}
	if !v.Since.IsZero() {
		r.since.Store(v.Since.UnixNano())
	}
	return nil
}

// Save writes the counters to path atomically: a temporary file in the same
// directory is written, synced and renamed over path.
func (r *Registry) Save(path string, now time.Time) error {
	s := r.Snapshot()
	v := file{Version: fileVersion, SavedAt: now.UTC(), Since: s.Since.UTC(), Total: s.Total,
		Inbounds: map[string]Traffic{}, Outbounds: map[string]Traffic{}, Groups: map[string]Traffic{}, Rules: map[string]RuleTraffic{}}
	for _, n := range s.Inbounds {
		v.Inbounds[n.Name] = n.Traffic
	}
	for _, n := range s.Outbounds {
		v.Outbounds[n.Name] = n.Traffic
	}
	for _, n := range s.Groups {
		v.Groups[n.Name] = n.Traffic
	}
	for _, n := range s.Rules {
		v.Rules[n.Name] = n.RuleTraffic
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if e := tmp.Chmod(0o600); e != nil && !isUnsupported(e) {
		return e
	}
	if _, e := tmp.Write(b); e != nil {
		return e
	}
	if e := tmp.Sync(); e != nil {
		return e
	}
	if e := tmp.Close(); e != nil {
		return e
	}
	if e := os.Rename(name, path); e != nil {
		return e
	}
	ok = true
	syncDir(dir)
	return nil
}

// QuarantineCorrupt renames an unreadable statistics file aside so that it
// can be inspected; the next save then starts a fresh file.
func QuarantineCorrupt(path string, now time.Time) (string, error) {
	to := fmt.Sprintf("%s.corrupt-%s", path, now.UTC().Format("20060102T150405Z"))
	return to, os.Rename(path, to)
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func isUnsupported(e error) bool { return errors.Is(e, errors.ErrUnsupported) }
