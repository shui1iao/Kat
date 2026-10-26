//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
)

// defaultDirs: root uses /run/kat (socket) and /var/lib/kat (statistics).
// Other users use $XDG_RUNTIME_DIR/kat (else /tmp/kat-UID) and
// $XDG_STATE_HOME/kat (else ~/.local/state/kat).
func defaultDirs() (run, state string) {
	if os.Geteuid() == 0 {
		return "/run/kat", "/var/lib/kat"
	}
	return userRunDir(), userStateDir()
}

func userRunDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "kat")
	}
	return filepath.Join(os.TempDir(), "kat-"+strconv.Itoa(os.Geteuid()))
}

func userStateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "kat")
	}
	if h, e := os.UserHomeDir(); e == nil && h != "" {
		return filepath.Join(h, ".local", "state", "kat")
	}
	return filepath.Join(os.TempDir(), "kat-"+strconv.Itoa(os.Geteuid()))
}

// socketCandidates lists where an instance's socket may be, preferred first:
// the system path (a root service) and this user's own runtime path.
func socketCandidates(name string) []string {
	sys := filepath.Join("/run/kat", name+".sock")
	if os.Geteuid() == 0 {
		return []string{sys}
	}
	return []string{sys, filepath.Join(userRunDir(), name+".sock")}
}
