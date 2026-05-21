//go:build windows && !fyne

package main

import (
	"io"
	"log"
	"os"

	"github.com/lxn/walk"

	"github.com/atlanteg/supervpn/internal/update"
)

func main() {
	// Request administrator privileges — required for WinTun/TAP adapter
	// creation, pnputil driver install, netsh IP assignment, and Npcap capture.
	// If not elevated, relaunches via UAC and exits this instance.
	ensureAdmin()

	if lf := openLogFile(); lf != nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}

	defer func() {
		if r := recover(); r != nil {
			writeCrashReport(r)
			walk.MsgBox(nil, "superVPN — Fatal Error",
				"The application crashed. See crash.txt in %AppData%\\superVPN for details.",
				walk.MsgBoxIconError)
		}
	}()

	update.CleanupOldFiles()
	go update.CheckAndUpdate(version, update.AssetForClientGUI(), nil)

	ui := &winUI{}
	ui.runApp()
}
