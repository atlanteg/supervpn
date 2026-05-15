//go:build darwin

package main

import (
	"log"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

// bridgeName returns the physical NIC name for BPF binding on macOS.
// BPF binds directly to the NIC, so there's no separate virtual adapter.
func bridgeName(_, detectedNIC string) string { return detectedNIC }

func openDirectFramer(_ config.BridgeConfig, tunName string) (bridge.Framer, string, error) {
	f, err := pkgtun.Open(tunName)
	if err != nil {
		return nil, "", err
	}
	return f, tunName, nil
}

func openPlatformBridge(bc config.BridgeConfig, detected bridge.Interface, adapterName string) (bridge.Framer, error) {
	if err := ensureBridge(bc, detected.Name, adapterName); err != nil {
		log.Printf("bridge: setup warning: %v", err)
	}
	return pkgtun.OpenBridge(adapterName)
}
