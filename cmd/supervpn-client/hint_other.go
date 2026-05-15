//go:build !darwin

package main

import (
	"log"

	"github.com/atlanteg/supervpn/internal/config"
)

func bridgeSetupHint(bc config.BridgeConfig) {
	switch bc.SetupMethod {
	case "hyperv":
		log.Printf("bridge setup (hyperv): run deploy\\setup-bridge-hyperv.ps1 -PhysicalNIC <nic-name> once, then restart supervpn-client")
	default:
		log.Printf("bridge setup (netbridge): run deploy\\setup-bridge-netbridge.ps1 -PhysicalNIC <nic-name> once, or bridge manually in ncpa.cpl")
	}
}
