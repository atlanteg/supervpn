//go:build windows

package tun

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/atlanteg/supervpn/internal/bridge"
)

// OpenBridge opens a tap-windows6 TAP adapter for L2 Ethernet bridging.
// name is the adapter name as shown in ncpa.cpl (e.g. "supervpn-tap").
func OpenBridge(name string) (bridge.Framer, error) {
	return OpenTAP(name)
}

// IsHyperVHost reports whether the current machine has Hyper-V enabled.
// Detected by the presence of the vmbus kernel service in the registry.
func IsHyperVHost() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\vmbus`, registry.READ)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// IsVEthernetAdapter reports whether the adapter name looks like a Hyper-V
// virtual Ethernet adapter (vEthernet (*)). These adapters are the right
// capture target on Hyper-V hosts but NDISUIO cannot bind to them — only
// Npcap/WinPcap can capture raw L2 frames on them.
func IsVEthernetAdapter(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "vethernet")
}

// OpenBridgeMulti tries L2 capture methods in order for physNIC, best-first:
//  1. Npcap/WinPcap — load wpcap.dll dynamically, direct raw L2 capture.
//     Works on both physical NICs and Hyper-V vEthernet adapters.
//  2. NDISUIO — built-in Windows NDIS user-mode I/O driver.
//     Does NOT work on Hyper-V vEthernet adapters.
//  3. tap+wbridge — tap-windows6 TAP + Windows Network Bridge (last resort).
//     Does NOT work when Hyper-V controls the NIC.
//
// Returns the framer and the method name used ("npcap", "ndisuio", "tap+wbridge").
func OpenBridgeMulti(physNIC, tapName string) (bridge.Framer, string, error) {
	hyperv := IsHyperVHost()
	veth := IsVEthernetAdapter(physNIC)

	if hyperv {
		log.Printf("bridge: Hyper-V host detected; adapter %q is vEthernet=%v", physNIC, veth)
		if veth && !NpcapInstalled() {
			log.Printf("bridge: WARNING — Npcap required on Hyper-V hosts for raw L2 capture on vEthernet adapters. Install Npcap from the application window.")
		}
	}

	if f, err := openNpcapFramer(physNIC); err == nil {
		return f, "npcap", nil
	} else {
		log.Printf("bridge: npcap unavailable: %v", err)
	}

	if veth {
		// NDISUIO cannot bind to Hyper-V vEthernet adapters — skip and give a
		// clear message rather than a confusing IOCTL error.
		log.Printf("bridge: skipping ndisuio for vEthernet adapter %q (not supported by Hyper-V vmswitch)", physNIC)
	} else {
		if f, err := openNDISUIOFramer(physNIC); err == nil {
			return f, "ndisuio", nil
		} else {
			log.Printf("bridge: ndisuio unavailable: %v", err)
		}
	}

	if hyperv {
		log.Printf("bridge: skipping tap+wbridge on Hyper-V host (Windows blocks bridging of vEthernet adapters)")
		return nil, "", fmt.Errorf("bridge: Hyper-V host requires Npcap for bridge mode — install it via the application window")
	}

	log.Printf("bridge: falling back to tap+wbridge")
	f, err := OpenTAP(tapName)
	if err != nil {
		return nil, "", fmt.Errorf("all capture methods failed: tap: %w", err)
	}
	return f, "tap+wbridge", nil
}
