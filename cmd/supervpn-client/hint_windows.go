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
	if name := findWinBridge(); name != "" {
		log.Printf("bridge: Windows Network Bridge %q already active (%q ↔ %q)", name, physicalNIC, tapName)
		return nil
	}
	log.Printf("bridge: creating Windows Network Bridge (%q ↔ %q) ...", physicalNIC, tapName)
	if err := bindMsBridge(physicalNIC, tapName); err != nil {
		return fmt.Errorf("%w — fallback: ncpa.cpl → select both adapters → Bridge Connections", err)
	}
	log.Printf("bridge: waiting for Network Bridge adapter to come up ...")
	time.Sleep(3 * time.Second)
	if name := findWinBridge(); name != "" {
		log.Printf("bridge: Network Bridge %q ready", name)
	} else {
		log.Printf("bridge: WARNING — Network Bridge adapter not detected after creation; " +
			"if no connectivity, create the bridge manually in ncpa.cpl")
	}
	return nil
}

// findWinBridge returns the name of the Windows "Network Bridge" (MAC Bridge Miniport)
// adapter if one exists, or empty string otherwise.
func findWinBridge() string {
	out, err := powershell(
		`Import-Module NetAdapter -Force; ` +
			`(Get-NetAdapter | Where-Object {` +
			`$_.InterfaceDescription -like '*MAC Bridge*' -or ` +
			`$_.InterfaceDescription -like '*Network Bridge*'` +
			`} | Select-Object -First 1 -ExpandProperty Name)`,
	)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// msBridgeBound returns true when the ms_bridge protocol is already enabled on nic.
func msBridgeBound(nic string) bool {
	cmd := fmt.Sprintf(
		`Import-Module NetAdapter -Force; (Get-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue).Enabled`,
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
//
// NetAdapter module must be imported explicitly — when PowerShell is invoked
// non-interactively without a profile, system modules are not auto-loaded.
func bindMsBridge(nic, tap string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
Import-Module NetAdapter -Force
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
