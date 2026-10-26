//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly)

package stats

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrLocked: another running Kat instance owns this statistics file.
var ErrLocked = errors.New("stats: statistics file is used by another instance")

// Lock creates the lock file exclusively while the instance runs. A lock file
// left by a crashed process is taken over when it can be removed (Windows
// refuses removal while the owning process keeps it open).
func Lock(path string) (release func(), err error) {
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return nil, e
	}
	name := path + ".lock"
	f, e := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(e, os.ErrExist) {
		if os.Remove(name) != nil {
			return nil, ErrLocked
		}
		f, e = os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	}
	if e != nil {
		return nil, ErrLocked
	}
	return func() { f.Close(); os.Remove(name) }, nil
}

func syncDir(string) {}
