//go:build windows && !fyne

package main

import (
	"io"
	"log"

	"github.com/lxn/walk"

	"github.com/atlanteg/supervpn/internal/update"
)

func main() {
	// Single-instance guard: if another copy is already running, bring its
	// window to the foreground and exit. Must run before ensureAdmin so that
	// the non-elevated launcher releases the mutex before the elevated
	// re-launch acquires it.
	if !acquireSingleInstance() {
		return
	}

	// Request administrator privileges — required for WinTun/TAP adapter
	// creation, pnputil driver install, netsh IP assignment, and Npcap capture.
	// If not elevated, relaunches via UAC and exits this instance.
	ensureAdmin()

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
