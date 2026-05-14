// Package tun provides platform-specific frame capture/inject.
// The Framer interface is implemented per OS in separate files:
//   tun_linux.go   — Linux TAP via /dev/net/tun (Ethernet frames)
//   tun_windows.go — Windows WinTun driver (raw IP packets)
//   tun_darwin.go  — macOS utun via SYSPROTO_CONTROL (raw IP packets)
package tun

import "github.com/atlanteg/supervpn/internal/bridge"

// Open opens or creates a TAP interface by name and returns a Framer.
// On Windows, the WinTun driver is used. On Linux, a kernel TAP device.
func Open(ifaceName string) (bridge.Framer, error) {
	return openPlatform(ifaceName)
}
