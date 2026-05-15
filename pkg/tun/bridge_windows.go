//go:build windows

package tun

import "github.com/atlanteg/supervpn/internal/bridge"

// OpenBridge opens a tap-windows6 TAP adapter for L2 Ethernet bridging.
// name is the adapter name as shown in ncpa.cpl (e.g. "supervpn-tap").
func OpenBridge(name string) (bridge.Framer, error) {
	return OpenTAP(name)
}
