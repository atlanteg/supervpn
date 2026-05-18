package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/atlanteg/supervpn/internal/update"
)

var version = "dev"

func main() {
	// Open persistent log file so crashes leave evidence after the process exits.
	if lf := openLogFile(); lf != nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}

	// Catch Go panics and write a crash report before exiting.
	defer func() {
		if r := recover(); r != nil {
			writeCrashReport(r)
			panic(r) // re-panic so the OS sees a non-zero exit
		}
	}()

	a := app.NewWithID("com.atlanteg.supervpn")

	// Check for updates in the background; mirrors are populated later from the
	// last-used server preference stored by the UI.
	mirrors := loadSavedMirrors(a)
	go update.CheckAndUpdate(version, update.AssetForClientGUI(), mirrors)

	w := a.NewWindow("superVPN " + version + " by NBTboost creators © Atlanteg")
	w.SetMaster()
	ui := newMainUI(a, w)
	w.SetContent(ui.build())
	w.Resize(fyne.NewSize(540, 640))

	// Populate config dropdown from *.toml files next to the binary.
	ui.initConfigSelect()

	w.ShowAndRun()
}

// openLogFile opens (or creates) a persistent log file in the user config dir.
// Each run appends a header line so sessions are distinguishable.
// Returns nil if the file cannot be opened — the caller falls back to stderr.
func openLogFile() *os.File {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	logDir := filepath.Join(dir, "superVPN")
	_ = os.MkdirAll(logDir, 0755)
	path := filepath.Join(logDir, "supervpn.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil
	}
	fmt.Fprintf(f, "\n=== superVPN %s started %s ===\n",
		version, time.Now().Format(time.RFC3339))
	return f
}

// writeCrashReport saves panic info + stack trace next to the log file so it
// survives even if the log file handle is closed before the OS flushes buffers.
func writeCrashReport(r interface{}) {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "superVPN", "crash.txt")
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "superVPN %s crashed at %s\n\npanic: %v\n\n%s\n",
		version, time.Now().Format(time.RFC3339), r, debug.Stack())
	log.Printf("crash report written to %s", path)
}

// loadSavedMirrors returns update mirror URLs derived from the last server
// address saved in Fyne preferences, mirroring the CLI auto-derive logic.
func loadSavedMirrors(a fyne.App) []string {
	server := a.Preferences().String("last_server")
	if server == "" {
		return nil
	}
	i := len(server) - 1
	for i >= 0 && server[i] != ':' {
		i--
	}
	host := server
	if i > 0 {
		host = server[:i]
	}
	if host == "" {
		return nil
	}
	return []string{"http://" + host + "/update"}
}
