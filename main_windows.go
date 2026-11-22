//go:build windows

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// notifyStopSignals delivers Ctrl-C and SIGTERM to ch.
func notifyStopSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

// terminateProcess asks the process to shut down. Windows has no
// SIGTERM, so this is the same as killProcess.
func terminateProcess(pid int) error {
	return killProcess(pid)
}

// killProcess force-kills the process.
func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
