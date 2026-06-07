//go:build windows

// Package winfirewall disables / restores the Windows Firewall for all
// profiles (Domain, Private, Public) via netsh.
//
// Both supervpn clients already require elevated privileges, so netsh
// will not prompt for UAC.  The caller is responsible for restoring the
// firewall state on exit (e.g. via defer winfirewall.Enable()).
package winfirewall

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// Disable turns off Windows Firewall for all profiles.
func Disable() error {
	return run("off")
}

// Enable turns on Windows Firewall for all profiles.
func Enable() error {
	return run("on")
}

// run invokes netsh with a hard 10 s timeout. netsh can hang indefinitely when
// the Windows Firewall service is stopped/disabled or in a bad state (seen on
// Server 2008 R2); without the timeout that would block app startup (window
// never shows) or shutdown (process won't exit / can't be killed).
func run(state string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles", "state", state)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
