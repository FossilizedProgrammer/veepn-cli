//go:build !windows

package config

import "syscall"

// processRunning reports whether pid is a live process.
func processRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
