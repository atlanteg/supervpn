//go:build windows

package tun

import (
	"os/exec"
	"syscall"
)

// hideWindow marks cmd so its console window is never shown on screen.
// Applies to background tools (netsh, pnputil, powershell) that would otherwise
// flash a black CMD window for a fraction of a second when the client connects.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
