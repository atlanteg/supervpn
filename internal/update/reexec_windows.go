//go:build windows

package update

import (
	"log"
	"os"
	"os/exec"
	"syscall"
)

var (
	modUser32                 = syscall.NewLazyDLL("user32.dll")
	procAllowSetForegroundWin = modUser32.NewProc("AllowSetForegroundWindow")
)

func reexec(exe string) {
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		log.Printf("update: restart: %v — restart manually", err)
		return
	}
	// Grant the newly-spawned process the right to call SetForegroundWindow so
	// the updated window appears in front of other windows, not behind them.
	const ASFW_ANY = ^uintptr(0) // (DWORD)-1
	_, _, _ = procAllowSetForegroundWin.Call(ASFW_ANY)
	os.Exit(0)
}
