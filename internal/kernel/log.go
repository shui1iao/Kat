package kernel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Log levels. Existing 0.6.3 lines keep their text; only the level decides
// whether a line is written. failure and *_update_failed events are warn,
// other operational events info, management/persistence details debug.
type logLevel int32

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

var levelNames = [...]string{"debug", "info", "warn", "error"}

func (l logLevel) String() string {
	if l < levelDebug || l > levelError {
		return "info"
	}
	return levelNames[l]
}

// parseLevel accepts the configured/requested level name ("" = info).
func parseLevel(s string) (logLevel, bool) {
	switch strings.ToLower(s) {
	case "", "info":
		return levelInfo, true
	case "debug":
		return levelDebug, true
	case "warn", "warning":
		return levelWarn, true
	case "error":
		return levelError, true
	}
	return levelInfo, false
}

// logger is the single sink of one Server. Text format on stderr writes the
// lines exactly as 0.6.3 did; a file sink prefixes an RFC 3339 timestamp; the
// JSON format converts "kat event=NAME k=v ..." lines into one object each.
type logger struct {
	level  atomic.Int32
	json   bool
	access atomic.Bool
	file   *rotatingFile // nil = stderr
	write  func([]byte) error
	close  func()
	mu     sync.Mutex // serializes close against in-flight writes
	closed bool
	now    func() time.Time
}

func newLogger(o *LogOptions) (*logger, error) {
	l := &logger{now: time.Now}
	lv := levelInfo
	if o != nil {
		lv, _ = parseLevel(o.Level)
		l.json = o.Format == "json"
		l.access.Store(o.Access)
		if o.File != "" {
			f, e := openRotatingFile(o.File, int64(o.MaxSizeMB)<<20, o.MaxBackups)
			if e != nil {
				return nil, e
			}
			l.file = f
			l.write = f.Write
			l.close = func() { _ = f.Close() }
		}
	}
	if l.write == nil {
		l.write, l.close = diagnosticStderr()
	}
	l.level.Store(int32(lv))
	return l, nil
}

func (l *logger) enabled(lv logLevel) bool {
	return l != nil && lv >= logLevel(l.level.Load())
}

func (l *logger) setLevel(lv logLevel) { l.level.Store(int32(lv)) }
func (l *logger) getLevel() logLevel   { return logLevel(l.level.Load()) }

// emit writes one complete line (ending in '\n') when lv is enabled. The
// returned error is the sink error so that callers keep their 0.6.3
// suppression accounting for an unavailable sink.
func (l *logger) emit(lv logLevel, line []byte) error {
	if !l.enabled(lv) {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("log closed")
	}
	out := line
	if l.json {
		out = jsonLine(l.now(), lv, line)
	} else if l.file != nil {
		ts := l.now().Format(time.RFC3339Nano)
		out = make([]byte, 0, len(ts)+len(line)+1)
		out = append(out, ts...)
		out = append(out, ' ')
		out = append(out, line...)
	}
	return l.write(out)
}

// replaceSink adopts the destination and format of n (a reload changed
// log.file, log.format or rotation) and closes the previous destination.
// Level and access setting stay with l.
func (l *logger) replaceSink(n *logger) {
	l.mu.Lock()
	oldClose := l.close
	l.json, l.file, l.write, l.close = n.json, n.file, n.write, n.close
	closed := l.closed
	l.mu.Unlock()
	if oldClose != nil && !closed {
		oldClose()
	}
}

func (l *logger) shutdown() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		if l.close != nil {
			l.close()
		}
	}
}

// jsonLine converts a text line. "kat event=NAME k=v ..." becomes
// {"time":..,"level":..,"event":"NAME","k":"v",...}; digits-only values
// become numbers. Any other line becomes {"time","level","msg"}.
func jsonLine(now time.Time, lv logLevel, line []byte) []byte {
	s := strings.TrimRight(string(line), "\n")
	b := make([]byte, 0, len(s)+64)
	b = append(b, `{"time":`...)
	b = strconv.AppendQuote(b, now.Format(time.RFC3339Nano))
	b = append(b, `,"level":`...)
	b = strconv.AppendQuote(b, lv.String())
	if rest, ok := strings.CutPrefix(s, "kat "); ok && strings.HasPrefix(rest, "event=") {
		seen := map[string]bool{"time": true, "level": true}
		for _, f := range strings.Fields(rest) {
			k, v, ok := strings.Cut(f, "=")
			if !ok || seen[k] {
				continue
			}
			seen[k] = true
			b = append(b, ',')
			kb, _ := json.Marshal(k)
			b = append(b, kb...)
			b = append(b, ':')
			if isDigits(v) && len(v) < 19 {
				b = append(b, v...)
			} else {
				vb, _ := json.Marshal(v)
				b = append(b, vb...)
			}
		}
	} else {
		b = append(b, `,"msg":`...)
		mb, _ := json.Marshal(s)
		b = append(b, mb...)
	}
	return append(b, '}', '\n')
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) == 1 || s[0] != '0'
}

// rotatingFile appends to path and, before a write would exceed max bytes,
// renames path -> path.1 -> ... -> path.N (N = backups) and starts a new file.
// backups 0 truncates instead. Files are created 0600.
type rotatingFile struct {
	mu      sync.Mutex
	path    string
	max     int64
	backups int
	f       *os.File
	size    int64
}

func openRotatingFile(path string, max int64, backups int) (*rotatingFile, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0o750); e != nil {
		return nil, e
	}
	r := &rotatingFile{path: path, max: max, backups: backups}
	if e := r.open(); e != nil {
		return nil, e
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, e := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) rotate() error {
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
	if r.backups == 0 {
		if e := os.Truncate(r.path, 0); e != nil && !os.IsNotExist(e) {
			return e
		}
		return r.open()
	}
	for i := r.backups - 1; i >= 1; i-- {
		_ = os.Rename(r.path+"."+strconv.Itoa(i), r.path+"."+strconv.Itoa(i+1))
	}
	if e := os.Rename(r.path, r.path+".1"); e != nil && !os.IsNotExist(e) {
		return e
	}
	return r.open()
}

func (r *rotatingFile) Write(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if e := r.open(); e != nil {
			return e
		}
	}
	if r.size > 0 && r.size+int64(len(b)) > r.max {
		if e := r.rotate(); e != nil {
			return e
		}
	}
	n, e := r.f.Write(b)
	r.size += int64(n)
	return e
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	e := r.f.Close()
	r.f = nil
	return e
}
