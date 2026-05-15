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
