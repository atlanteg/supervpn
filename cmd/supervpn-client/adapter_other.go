//go:build !darwin

package main

// bridgeName returns the virtual TAP adapter name on Windows/Linux.
// The TAP device is a separate virtual adapter that is then bridged to the NIC.
func bridgeName(tapName, _ string) string { return tapName }
