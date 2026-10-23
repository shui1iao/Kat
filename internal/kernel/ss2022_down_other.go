//go:build !linux

package kernel

// socketReadable is unknown off Linux: SS2022 download keeps relay-buffer records.
func socketReadable(uintptr) int { return 0 }
