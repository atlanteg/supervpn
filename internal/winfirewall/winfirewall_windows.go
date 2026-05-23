//go:build windows

// Package winfirewall disables / restores the Windows Firewall for all
// profiles (Domain, Private, Public) via netsh.
//
// Both supervpn clients already require elevated privileges, so netsh
// will not prompt for UAC.  The caller is responsible for restoring the
// firewall state on exit (e.g. via defer winfirewall.Enable()).
package winfirewall

import (
	"os/exec"
	"syscall"
)

// Disable turns off Windows Firewall for all profiles.
func Disable() error {
	return run("off")
}

// Enable turns on Windows Firewall for all profiles.
func Enable() error {
	return run("on")
}

func run(state string) error {
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", state)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
