//go:build windows && !fyne

package main

import (
	"io"
	"log"

	"github.com/lxn/walk"

	"github.com/atlanteg/supervpn/internal/update"
)

func main() {
	// Request administrator privileges FIRST — required for WinTun/TAP adapter
	// creation, pnputil driver install, netsh IP assignment, and Npcap capture.
	// If not elevated, relaunches via UAC and exits this instance. Doing this
	// before the single-instance guard means the throw-away non-elevated
	// launcher never touches the mutex, so the elevated instance acquires it
	// cleanly with no race (which previously left no window on slower hosts).
	ensureAdmin()

	// Single-instance guard (per-session): if another copy is already running
	// IN THIS SESSION, bring its window to the foreground and exit. The mutex is
	// session-local, so separate RDP sessions on a terminal server (e.g. Windows
	// Server 2008 R2) each run their own instance instead of blocking each other.
	if !acquireSingleInstance() {
		return
	}

	// Windows GUI apps have no console — writing to os.Stderr returns an error
	// which causes io.MultiWriter to short-circuit and drop subsequent writers.
	// Write only to the log file and the in-memory ring (AppLog).
	if lf := openLogFile(); lf != nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(lf, AppLog))
	} else {
		log.SetOutput(AppLog)
	}
	log.Printf("superVPN %s started", version)

	defer func() {
		if r := recover(); r != nil {
			writeCrashReport(r)
			walk.MsgBox(nil, "superVPN — Fatal Error",
				"The application crashed. See crash.txt in %AppData%\\superVPN for details.",
				walk.MsgBoxIconError)
		}
	}()

	update.CleanupOldFiles()
	go update.CheckAndUpdate(version, update.AssetForClientGUI(), update.DefaultMirrors())

	ui := &winUI{}
	ui.runApp()
}
