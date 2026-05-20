//go:build windows

package clientadapter

import (
	"os/exec"
	"syscall"
)

// hideWindow marks cmd so its console window stays hidden.
// Prevents powershell/netsh subprocess windows from flashing in front of the user.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
