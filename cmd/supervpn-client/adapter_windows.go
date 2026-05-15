//go:build windows

package main

import (
	"log"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

// bridgeName returns the virtual TAP adapter name on Windows.
func bridgeName(tapName, _ string) string { return tapName }

// openDirectFramer opens the tap-windows6 TAP adapter (L2) in direct mode so
// that the client participates in the hub's L2 broadcast domain with full
// Ethernet framing and ARP — exactly like a bridge-mode client but without a
// physical NIC being bridged.
func openDirectFramer(bc config.BridgeConfig, _ string) (bridge.Framer, string, error) {
	f, err := pkgtun.OpenTAP(bc.TapName)
	if err != nil {
		return nil, "", err
	}
	return f, bc.TapName, nil
}

func openPlatformBridge(bc config.BridgeConfig, detected bridge.Interface, adapterName string) (bridge.Framer, error) {
	framer, method, err := pkgtun.OpenBridgeMulti(detected.Name, bc.TapName)
	if err != nil {
		return nil, err
	}
	log.Printf("bridge: capture method: %s", method)
	// Only set up the OS-level Network Bridge when falling back to tap+wbridge,
	// since Npcap and NDISUIO capture directly from the physical NIC.
	if method == "tap+wbridge" {
		if err := ensureBridge(bc, detected.Name, adapterName); err != nil {
			log.Printf("bridge: OS bridge warning: %v", err)
		}
	}
	return framer, nil
}
