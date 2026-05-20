//go:build windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// ensureAdmin checks if the process is running with administrator privileges.
// If not, it relaunches itself via ShellExecuteW with the "runas" verb so
// Windows shows the UAC consent dialog, then exits the current (non-elevated)
// instance.  Returns true if already elevated (caller can proceed normally).
func ensureAdmin() bool {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	if elevated {
		return true
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

	err = windows.ShellExecute(0, verbPtr, exePtr, argsPtr, nil, windows.SW_NORMAL)
	if err == nil {
		// Successfully launched elevated instance — exit this one.
		os.Exit(0)
	}
	// User cancelled UAC or ShellExecute failed — continue without elevation.
	return false
}
