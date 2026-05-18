package clientadapter

import (
	"fmt"
	"log"
	"strings"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

// OpenAdapter opens the virtual adapter for this session.
func OpenAdapter(cfg config.ClientConfig) (bridge.Interface, bridge.Framer, error) {
	if cfg.Mode == "direct" {
		log.Printf("adapter: mode=direct (forced via config)")
		return openDirectAdapter(cfg)
	}

	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		return bridge.Interface{}, nil, fmt.Errorf("detect interfaces: %w", err)
	}

	bc := cfg.Bridge.WithDefaults()
	tunName := cfg.TunName
	if tunName == "" {
		tunName = "supervpn"
	}
	var physical []bridge.Interface
	for _, iface := range ifaces {
		if iface.Name == bc.TapName || iface.Name == tunName {
			log.Printf("bridge: ignoring own VPN adapter %q", iface.Name)
			continue
		}
		if strings.Contains(iface.Name, "*") {
			log.Printf("bridge: skipping virtual adapter %q", iface.Name)
			continue
		}
		if strings.Contains(strings.ToLower(iface.Name), "vpn") {
			log.Printf("bridge: skipping VPN adapter %q (use bridge.nic in config to override)", iface.Name)
			continue
		}
		if len(iface.HWAddr) >= 2 && iface.HWAddr[0] == 0x00 && iface.HWAddr[1] == 0xFF {
			log.Printf("bridge: skipping TAP adapter %q mac=%s (use bridge.nic in config to override)", iface.Name, iface.HWAddr)
			continue
		}
		physical = append(physical, iface)
	}

	if bc.NIC != "" {
		for _, iface := range physical {
			if iface.Name == bc.NIC {
				return openBridgeAdapter(cfg, iface)
			}
		}
		log.Printf("bridge: configured nic %q not found among 169.254 interfaces — falling back to direct mode", bc.NIC)
		return openDirectAdapter(cfg)
	}

	if cfg.Mode == "bridge" && len(physical) == 0 {
		return bridge.Interface{}, nil, fmt.Errorf("adapter: mode=bridge but no 169.254.0.0/16 interface found")
	}
	if len(physical) > 0 {
		iface, framer, err := openBridgeAdapter(cfg, physical[0])
		if err != nil {
			if cfg.Mode == "bridge" {
				return bridge.Interface{}, nil, err
			}
			log.Printf("bridge: failed to open bridge adapter: %v — falling back to direct mode", err)
			return openDirectAdapter(cfg)
		}
		return iface, framer, nil
	}
	return openDirectAdapter(cfg)
}

func openBridgeAdapter(cfg config.ClientConfig, detected bridge.Interface) (bridge.Interface, bridge.Framer, error) {
	bc := cfg.Bridge.WithDefaults()

	adapterName := bridgeAdapterName(bc.TapName, detected.Name)

	log.Printf("bridge mode: bridging local NIC %q (addr=%s mac=%s) → %q",
		detected.Name, detected.Addr, detected.HWAddr, adapterName)

	framer, err := openPlatformBridge(bc, detected, adapterName)
	if err != nil {
		return bridge.Interface{}, nil, fmt.Errorf("open bridge adapter %q: %w", adapterName, err)
	}

	actual := pkgtun.ActualName(framer, adapterName)
	log.Printf("bridge mode: adapter %q open", actual)

	return detected, framer, nil
}

func bridgeAdapterName(tapName, detectedNIC string) string {
	return bridgeName(tapName, detectedNIC)
}

func openDirectAdapter(cfg config.ClientConfig) (bridge.Interface, bridge.Framer, error) {
	tunName := cfg.TunName
	if tunName == "" {
		tunName = "supervpn"
	}
	bc := cfg.Bridge.WithDefaults()

	framer, actual, err := openDirectFramer(bc, tunName)
	if err != nil {
		return bridge.Interface{}, nil, fmt.Errorf("open direct adapter %q: %w", tunName, err)
	}
	log.Printf("direct mode: opened %q (L2 TAP — participates in hub L2 domain)", actual)
	return bridge.Interface{Name: actual}, framer, nil
}
