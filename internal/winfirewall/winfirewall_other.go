//go:build !windows

package winfirewall

// Disable is a no-op on non-Windows platforms.
func Disable() error { return nil }

// Enable is a no-op on non-Windows platforms.
func Enable() error { return nil }
