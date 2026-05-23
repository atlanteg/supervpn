package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// AppLog is a global in-memory ring buffer that receives every line written
// to the standard logger (log.Printf / log.Print / log.Println).
// The UI Log tab reads from it so all subsystem output — VPN client, ZGW
// discovery, update checker, firewall — is visible without opening a file.
var AppLog = newRingWriter(500)

// ringWriter is a thread-safe line-oriented io.Writer backed by a fixed-size
// circular slice.  It is wired into log.SetOutput alongside the log file.
type ringWriter struct {
	mu      sync.Mutex
	lines   []string
	version uint64
	max     int
}

func newRingWriter(max int) *ringWriter {
	return &ringWriter{max: max}
}

func (r *ringWriter) Write(p []byte) (n int, err error) {
	line := strings.TrimRight(string(p), "\r\n")
	if line == "" {
		return len(p), nil
	}
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		copy(r.lines, r.lines[len(r.lines)-r.max:])
		r.lines = r.lines[:r.max]
	}
	r.version++
	r.mu.Unlock()
	return len(p), nil
}

// Lines returns a snapshot of the current log lines.
func (r *ringWriter) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

// Version returns a counter incremented on every new line.
// UI components can compare against their last-seen value to skip repaints.
func (r *ringWriter) Version() uint64 {
	r.mu.Lock()
	v := r.version
	r.mu.Unlock()
	return v
}

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
