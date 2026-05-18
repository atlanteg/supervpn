package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// openLogFile opens (or creates) a persistent log file in the user config dir.
// Each run appends a session header. Returns nil if the file cannot be opened.
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

// writeCrashReport saves panic info + stack trace to crash.txt next to supervpn.log.
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
