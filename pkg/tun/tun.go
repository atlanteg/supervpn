// Package tun provides platform-specific frame capture/inject.
// The Framer interface is implemented per OS in separate files:
//   tun_linux.go   — Linux TAP via /dev/net/tun (Ethernet frames)
//   tun_windows.go — Windows WinTun driver (raw IP packets)
//   tun_darwin.go  — macOS utun via SYSPROTO_CONTROL (raw IP packets)
package tun

import "github.com/atlanteg/supervpn/internal/bridge"

// Namer is an optional interface implemented by platform TUN types that can
// report the OS-assigned interface name. On macOS the kernel auto-assigns a
// name (utun0, utun1, …) that differs from the name passed to Open.
type Namer interface {
	IfName() string
}

// Open opens or creates a TUN/TAP interface and returns a Framer.
// On Windows the WinTun driver is used; on Linux a kernel TAP device;
// on macOS a native utun device (name parameter is ignored).
func Open(ifaceName string) (bridge.Framer, error) {
	return openPlatform(ifaceName)
}

// ActualName returns the real OS interface name for the framer.
// Falls back to the requested name when the Namer interface is not implemented.
func ActualName(f bridge.Framer, requested string) string {
	if n, ok := f.(Namer); ok {
		return n.IfName()
	}
	return requested
}
