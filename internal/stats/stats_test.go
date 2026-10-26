package stats

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadByName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "s.json")
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := New([]string{"socks5/1", "ss/2"}, []string{"direct", "up"}, []string{"g"}, []string{"final->direct", "domain:x->up"}, now)
	r.Total.AddUp(10)
	r.Total.AddDown(20)
	r.Inbound("ss/2").AddUp(10)
	r.Outbound("up").AddDown(20)
	r.Group("g").AddDown(20)
	r.Rule("domain:x->up").Hit()
	r.Rule("domain:x->up").AddUp(10)
	if e := r.Save(path, now); e != nil {
		t.Fatal(e)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "a", ".*tmp*")); len(m) != 0 {
		t.Fatal("temporary file left", m)
	}
	// Different order and a removed key: values follow the names.
	q := New([]string{"ss/2"}, []string{"up", "direct"}, nil, []string{"domain:x->up", "final->direct"}, now.Add(time.Hour))
	if e := q.Load(path); e != nil {
		t.Fatal(e)
	}
	s := q.Snapshot()
	if s.Total != (Traffic{10, 20}) || s.Inbounds[0].Up != 10 || s.Outbounds[0].Name != "up" || s.Outbounds[0].Down != 20 || s.Rules[0].Hits != 1 || s.Rules[0].Up != 10 || !s.Since.Equal(now) {
		t.Fatalf("%+v", s)
	}
	q.Reset(now.Add(2 * time.Hour))
	s = q.Snapshot()
	if s.Total != (Traffic{}) || s.Rules[0].Hits != 0 || !s.Since.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("%+v", s)
	}
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	r := New(nil, nil, nil, nil, time.Now())
	if e := r.Load(filepath.Join(dir, "none.json")); e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{"", "{", `{"version":2}`, `{"version":1,"extra":1}`, `{"version":1}{}`, `[]`, `{"version":1,"total":{"up":-1}}`} {
		p := filepath.Join(dir, "bad.json")
		os.WriteFile(p, []byte(body), 0o600)
		if e := r.Load(p); !errors.Is(e, ErrCorrupt) {
			t.Errorf("%q: %v", body, e)
		}
		if r.Total.Load() != (Traffic{}) {
			t.Fatal("partial load")
		}
	}
	p := filepath.Join(dir, "bad.json")
	to, e := QuarantineCorrupt(p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(to); e != nil {
		t.Fatal(e)
	}
}

func TestRate(t *testing.T) {
	now := time.Now()
	r := New(nil, nil, nil, nil, now)
	if up, down, w := r.Rate(); up != 0 || down != 0 || w != 0 {
		t.Fatal("rate without samples")
	}
	for i := 0; i < 10; i++ {
		r.Total.AddUp(1000)
		r.Total.AddDown(500)
		r.Sample(now.Add(time.Duration(i) * time.Second))
	}
	up, down, w := r.Rate()
	if w != 5*time.Second || up != 1000 || down != 500 {
		t.Fatal(up, down, w)
	}
}

func TestLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	release, e := Lock(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Lock(p); !errors.Is(e, ErrLocked) {
		t.Fatal("second instance got the lock", e)
	}
	release()
	release2, e := Lock(p)
	if e != nil {
		t.Fatal(e)
	}
	release2()
}
