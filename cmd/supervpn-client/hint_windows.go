//go:build windows

package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/atlanteg/supervpn/internal/config"
)

// ensureBridge checks whether the Windows Network Bridge is already configured
// between physicalNIC and tapName, and creates it automatically if not.
//
// The bridge is created by binding the ms_bridge (Microsoft MAC Bridge) NDIS
// protocol to both adapters — the same operation ncpa.cpl performs when you
// select two adapters and choose "Bridge Connections". The client must be
// running as Administrator for Add-NetAdapterBinding to succeed.
func ensureBridge(_ config.BridgeConfig, physicalNIC, tapName string) error {
	if msBridgeBound(physicalNIC) {
		log.Printf("bridge: Windows Network Bridge already active (%q ↔ %q)", physicalNIC, tapName)
		return nil
	}
	log.Printf("bridge: creating Windows Network Bridge (%q ↔ %q) ...", physicalNIC, tapName)
	if err := bindMsBridge(physicalNIC, tapName); err != nil {
		return fmt.Errorf("%w — fallback: ncpa.cpl → select both adapters → Bridge Connections", err)
	}
	log.Printf("bridge: Windows Network Bridge created; waiting for adapters to come up")
	time.Sleep(3 * time.Second)
	return nil
}

// msBridgeBound returns true when the ms_bridge protocol is already enabled on nic.
func msBridgeBound(nic string) bool {
	cmd := fmt.Sprintf(
		`(Get-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue).Enabled`,
		psSingleQuote(nic),
	)
	out, err := powershell(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "True"
}

// bindMsBridge enables the ms_bridge NDIS binding on both adapters.
// This creates (or joins) the Windows Network Bridge, allowing L2 frames to
// flow between the physical NIC and the TAP adapter without user interaction.
func bindMsBridge(nic, tap string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
Add-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
Add-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
Enable-NetAdapterBinding -Name %s -ComponentID ms_bridge
Enable-NetAdapterBinding -Name %s -ComponentID ms_bridge
`,
		psSingleQuote(nic), psSingleQuote(tap),
		psSingleQuote(nic), psSingleQuote(tap),
	)
	out, err := powershell(script)
	if err != nil {
		return fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

func powershell(script string) (string, error) {
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command", script,
	).CombinedOutput()
	return string(out), err
}

// psSingleQuote wraps s in PowerShell single quotes, escaping any embedded
// single quotes by doubling them. Single-quoted strings are literal in
// PowerShell — wildcards like * are not expanded.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
