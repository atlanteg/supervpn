package main

import (
	"fmt"
	"time"
)

// version is set at build time via -ldflags "-X main.version=bN".
var version = "dev"

// formatAgo returns "Last disconnect: Xm Ys ago" or "" when t is zero.
func formatAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("Last disconnect: %dm %ds ago", m, s)
}

// predefinedServers is the built-in server list shown in the dropdown on all platforms.
var predefinedServers = []struct{ name, addr string }{
	{"RDVM", "185.108.16.16:5555"},
	{"ADVM", "212.48.224.5:5555"},
	{"RAVM", "81.27.241.25:5555"},
	{"HE2", "49.13.4.85:5555"},
	{"HE3", "162.55.48.218:5555"},
}
