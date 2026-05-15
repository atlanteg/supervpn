//go:build windows

package tun

import (
	"fmt"

	"github.com/atlanteg/supervpn/internal/bridge"
)

// OpenBridge opens a tap-windows6 TAP adapter for L2 Ethernet bridging.
// name is the adapter name as shown in ncpa.cpl (e.g. "supervpn-tap").
func OpenBridge(name string) (bridge.Framer, error) {
	return OpenTAP(name)
}

// OpenBridgeMulti tries L2 capture methods in order for physNIC, best-first:
//  1. Npcap/WinPcap — load wpcap.dll dynamically, direct raw L2 capture
//  2. NDISUIO — built-in Windows NDIS user-mode I/O driver
//  3. tap+wbridge — tap-windows6 TAP adapter + Windows Network Bridge (fallback)
//
// Returns the framer and the method name used ("npcap", "ndisuio", "tap+wbridge").
func OpenBridgeMulti(physNIC, tapName string) (bridge.Framer, string, error) {
	if f, err := openNpcapFramer(physNIC); err == nil {
		return f, "npcap", nil
	} else {
		log.Printf("bridge: npcap unavailable: %v", err)
	}
	if f, err := openNDISUIOFramer(physNIC); err == nil {
		return f, "ndisuio", nil
	} else {
		log.Printf("bridge: ndisuio unavailable: %v", err)
	}
	log.Printf("bridge: falling back to tap+wbridge")
	f, err := OpenTAP(tapName)
	if err != nil {
		return nil, "", fmt.Errorf("all capture methods failed: tap: %w", err)
	}
	return f, "tap+wbridge", nil
}
