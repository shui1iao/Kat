//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// defaultDirs: %ProgramData%\Kat for both the socket and the statistics
// (falling back to %LOCALAPPDATA%\Kat, then the temporary directory).
func defaultDirs() (run, state string) {
	d := baseDir()
	return d, d
}

func baseDir() string {
	for _, v := range []string{"ProgramData", "LOCALAPPDATA"} {
		if d := os.Getenv(v); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, "Kat")
		}
	}
	return filepath.Join(os.TempDir(), "Kat")
}

func socketCandidates(name string) []string {
	return []string{filepath.Join(baseDir(), name+".sock")}
}
