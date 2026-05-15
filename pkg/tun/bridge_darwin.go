//go:build darwin

package tun

import "github.com/atlanteg/supervpn/internal/bridge"

// OpenBridge opens a BPF device bound to ifaceName for L2 Ethernet bridging.
// Requires root (or BPF TCC exemption). The caller is responsible for
// ensuring the physical interface is the one with the 169.254.x.x address.
func OpenBridge(ifaceName string) (bridge.Framer, error) {
	return openBPF(ifaceName)
}
