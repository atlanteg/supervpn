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

	go update.CheckAndUpdate(version, update.AssetForClientGUI(), nil)

	ui := &winUI{}
	ui.runApp()
}
