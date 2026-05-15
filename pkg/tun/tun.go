// Package tun provides platform-specific frame capture/inject.
//
// Two adapter types are available on Windows:
//   Open()    — WinTun (L3, raw IP packets) — used for direct mode
//   OpenTAP() — tap-windows6 (L2, Ethernet frames) — used for bridge mode
//
// On Linux, Open() returns a kernel TAP device (L2, Ethernet frames).
// On macOS, Open() returns a native utun device (L3, raw IP packets).
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
