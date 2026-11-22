//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyStopSignals delivers Ctrl-C and SIGTERM to ch.
func notifyStopSignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
}

// terminateProcess asks the process to shut down.
func terminateProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// killProcess force-kills the process.
func killProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
