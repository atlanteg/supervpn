//go:build windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// elevationTriedEnv marks that this process tree has already attempted a runas
// relaunch, so a child must not try again.
const elevationTriedEnv = "SUPERVPN_ELEVATION_TRIED"

// ensureAdmin checks if the process is running with administrator privileges.
// If not, it relaunches itself via ShellExecuteW with the "runas" verb so
// Windows shows the UAC consent dialog, then exits the current (non-elevated)
// instance.  Returns true if already elevated (caller can proceed normally).
func ensureAdmin() bool {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	if elevated {
		return true
	}

	// Guard against an infinite silent relaunch loop: on hosts with UAC disabled
	// (EnableLUA=0), ShellExecute "runas" neither prompts nor actually elevates,
	// so IsElevated() keeps returning false and a naive relaunch respawns forever
	// (process flickers, CPU spins, the window never appears). Relaunch at most
	// once; if we are the relaunched child, proceed unelevated.
	if os.Getenv(elevationTriedEnv) == "1" {
		return false
	}

	// Not elevated — re-launch with runas.
	exe, err := os.Executable()
	if err != nil {
		return false
	}

	// Build the current command-line arguments string (skip argv[0]).
	args := ""
	if len(os.Args) > 1 {
		for i, a := range os.Args[1:] {
			if i > 0 {
				args += " "
			}
			args += syscall.EscapeArg(a)
		}
	}

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)

	var argsPtr *uint16
	if args != "" {
		argsPtr, _ = syscall.UTF16PtrFromString(args)
	}

	// Mark the attempt before launching so the child (which inherits this env
	// when UAC is off and runas does not actually cross an elevation boundary)
	// sees it and does not relaunch again.
	_ = os.Setenv(elevationTriedEnv, "1")

	err = windows.ShellExecute(0, verbPtr, exePtr, argsPtr, nil, windows.SW_NORMAL)
	if err == nil {
		// Successfully launched elevated instance — exit this one.
		os.Exit(0)
	}
	// User cancelled UAC or ShellExecute failed — continue without elevation.
	return false
}
