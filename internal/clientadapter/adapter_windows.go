//go:build windows

package clientadapter

import (
	"log"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

func bridgeName(tapName, _ string) string { return tapName }

func openDirectFramer(_ config.BridgeConfig, tunName string) (bridge.Framer, string, error) {
	// TAP first: tap-windows6 registers as IF_TYPE_ETHERNET_CSMACD (6), which is
	// required by BMW ENET discovery tools (Remote Enet, ZGW Search) that filter
	// GetAdaptersAddresses results by IfType == 6 and skip WinTun (type 53).
	ft, err := pkgtun.OpenTAP(tunName)
	if err == nil {
		log.Printf("direct: using TAP adapter %q (IF_TYPE_ETHERNET_CSMACD, BMW ENET compatible)", tunName)
		return ft, tunName, nil
	}
	log.Printf("direct: TAP unavailable (%v), falling back to WinTun L2", err)
	f, err2 := pkgtun.OpenWinTunL2Direct(tunName)
	if err2 != nil {
		return nil, "", err2
	}
	log.Printf("direct: using WinTun L2 adapter %q", tunName)
	return f, tunName, nil
}

func openPlatformBridge(bc config.BridgeConfig, detected bridge.Interface, adapterName string) (bridge.Framer, error) {
	framer, method, err := pkgtun.OpenBridgeMulti(detected.Name, bc.TapName)
	if err != nil {
		return nil, err
	}
	log.Printf("bridge: capture method: %s", method)
	if method == "tap+wbridge" {
		if err := ensureBridge(bc, detected.Name, adapterName); err != nil {
			log.Printf("bridge: OS bridge warning: %v", err)
		}
	}
	return framer, nil
}
