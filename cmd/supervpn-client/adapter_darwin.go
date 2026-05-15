//go:build darwin

package main

// bridgeName returns the physical NIC name for BPF binding on macOS.
// BPF binds directly to the NIC, so there's no separate virtual adapter.
func bridgeName(_, detectedNIC string) string { return detectedNIC }
