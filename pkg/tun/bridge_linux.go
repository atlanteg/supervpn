//go:build linux

package tun

import "github.com/atlanteg/supervpn/internal/bridge"

// OpenBridge opens a kernel TAP device for L2 Ethernet bridging.
// On Linux, Open() already returns a TAP device (L2, Ethernet frames).
func OpenBridge(name string) (bridge.Framer, error) {
	return openPlatform(name)
}
