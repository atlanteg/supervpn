package clientadapter

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/atlanteg/supervpn/internal/bridge"
	"github.com/atlanteg/supervpn/internal/config"
	pkgtun "github.com/atlanteg/supervpn/pkg/tun"
)

// OpenAdapter opens the virtual adapter for this session.
// The returned string describes the active mode, e.g. "bridge (en0)" or "direct (utun9)".
func OpenAdapter(cfg config.ClientConfig) (bridge.Interface, bridge.Framer, string, error) {
	if cfg.Mode == "direct" {
		log.Printf("adapter: mode=direct (forced via config)")
		iface, framer, err := openDirectAdapter(cfg)
		if err != nil {
			return iface, framer, "", err
		}
		return iface, framer, "direct (" + iface.Name + ")", nil
	}

	ifaces, err := bridge.DetectLinkLocal()
	if err != nil {
		return bridge.Interface{}, nil, "", fmt.Errorf("detect interfaces: %w", err)
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

	// Hard exclusion: never bridge Radmin VPN (Famatech) etc. A stale config can
	// carry it in bridge.nic (auto-detection's "vpn" filter only guards the
	// auto-pick, not an explicit NIC). Ignore it and fall through to normal
	// auto-detection instead of bridging it.
	if bc.NIC != "" && bridge.IsExcludedFromBridge(bc.NIC) {
		log.Printf("bridge: ignoring excluded bridge NIC %q (Radmin VPN etc.) — using auto-detection", bc.NIC)
		bc.NIC = ""
	}

	if bc.NIC != "" {
		for _, iface := range physical {
			if iface.Name == bc.NIC {
				ri, rf, err := openBridgeAdapter(cfg, iface)
				if err != nil {
					return ri, rf, "", err
				}
				return ri, rf, "bridge (" + iface.Name + ")", nil
			}
		}
		// The user explicitly picked this NIC, but it is not among the
		// auto-detected 169.254 interfaces (no APIPA address yet, or it was
		// filtered for some reason). Honour the choice as long as the adapter
		// exists, instead of silently dropping to direct mode — which looked
		// like "Connect does nothing" to the user.
		if ni, err := net.InterfaceByName(bc.NIC); err == nil {
			log.Printf("bridge: NIC %q has no 169.254 address but was explicitly selected — bridging it anyway", bc.NIC)
			chosen := bridge.Interface{Name: ni.Name, HWAddr: ni.HardwareAddr}
			ri, rf, err := openBridgeAdapter(cfg, chosen)
			if err != nil {
				return ri, rf, "", err
			}
			return ri, rf, "bridge (" + ni.Name + ")", nil
		}
		log.Printf("bridge: configured nic %q not found on this system — falling back to direct mode", bc.NIC)
		iface, framer, err := openDirectAdapter(cfg)
		if err != nil {
			return iface, framer, "", err
		}
		return iface, framer, "direct (" + iface.Name + ")", nil
	}

	if cfg.Mode == "bridge" && len(physical) == 0 {
		return bridge.Interface{}, nil, "", fmt.Errorf("adapter: mode=bridge but no 169.254.0.0/16 interface found")
	}
	if len(physical) > 0 {
		iface, framer, err := openBridgeAdapter(cfg, physical[0])
		if err != nil {
			if cfg.Mode == "bridge" {
				return bridge.Interface{}, nil, "", err
			}
			log.Printf("bridge: failed to open bridge adapter: %v — falling back to direct mode", err)
			di, df, err := openDirectAdapter(cfg)
			if err != nil {
				return di, df, "", err
			}
			return di, df, "direct (" + di.Name + ")", nil
		}
		return iface, framer, "bridge (" + physical[0].Name + ")", nil
	}
	iface, framer, err := openDirectAdapter(cfg)
	if err != nil {
		return iface, framer, "", err
	}
	return iface, framer, "direct (" + iface.Name + ")", nil
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

	if cfg.TunIP != "" {
		if err := assignAdapterIP(actual, cfg.TunIP); err != nil {
			log.Printf("direct mode: TUN IP warning: %v", err)
		} else {
			log.Printf("direct mode: %s: assigned static IP %s", actual, cfg.TunIP)
		}
	}

	return bridge.Interface{Name: actual}, framer, nil
}
