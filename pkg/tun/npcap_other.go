//go:build !windows

package tun

// NpcapInstalled always returns true on non-Windows platforms — Npcap is a
// Windows-only driver, so the Install button is never shown on macOS/Linux.
func NpcapInstalled() bool { return true }

// InstallNpcap is a no-op on non-Windows platforms.
func InstallNpcap() error { return nil }
