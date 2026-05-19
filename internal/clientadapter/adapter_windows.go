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
	// OpenWinTunL2Direct also assigns 169.254.x.y to the adapter so that
	// link-local discovery tools (BMW ENET Remote Enet, ZGW Search, etc.)
	// find it via GetAdaptersAddresses and route broadcasts through the VPN.
	f, err := pkgtun.OpenWinTunL2Direct(tunName)
	if err == nil {
		log.Printf("direct: using WinTun L2 adapter %q", tunName)
		return f, tunName, nil
	}
	log.Printf("direct: WinTun unavailable (%v), falling back to tap-windows6", err)
	ft, err2 := pkgtun.OpenTAP(tunName)
	if err2 != nil {
		return nil, "", err2
	}
	return ft, tunName, nil
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
