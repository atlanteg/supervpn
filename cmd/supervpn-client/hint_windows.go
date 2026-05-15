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
// Requires Administrator — Add-NetAdapterBinding (ms_bridge NDIS binding) is
// an elevated operation. If not elevated, logs a warning and returns nil so
// the rest of the VPN session still starts.
func ensureBridge(_ config.BridgeConfig, physicalNIC, tapName string) error {
	if name := findWinBridge(); name != "" {
		log.Printf("bridge: Windows Network Bridge %q already active (%q ↔ %q)", name, physicalNIC, tapName)
		return nil
	}

	if !isElevated() {
		log.Printf("bridge: WARNING — not running as Administrator; cannot auto-create bridge")
		log.Printf("bridge: right-click supervpn-client.exe → \"Run as administrator\", or create bridge manually in ncpa.cpl")
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

// isElevated returns true when the current process has Administrator privileges.
func isElevated() bool {
	out, err := powershell(`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "True"
}

// findWinBridge returns the name of the Windows "Network Bridge" (MAC Bridge Miniport)
// adapter if one exists, or empty string otherwise.
func findWinBridge() string {
	out, err := powershell(
		`Import-Module NetAdapter -Force -ErrorAction SilentlyContinue; ` +
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
		`Import-Module NetAdapter -Force -ErrorAction SilentlyContinue; (Get-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue).Enabled`,
		psSingleQuote(nic),
	)
	out, err := powershell(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "True"
}

// bindMsBridge enables the ms_bridge NDIS binding on both adapters.
//
// On Windows 8+ the NetAdapter module exposes Add-NetAdapterBinding and
// Enable-NetAdapterBinding. We guard with Get-Command so that on machines
// where only Enable- is present (binding already listed but disabled) we
// still succeed.
func bindMsBridge(nic, tap string) error {
	// Diagnostic: show which binding-related cmdlets loaded successfully.
	diagOut, _ := powershell(`Import-Module NetAdapter -Force -ErrorAction SilentlyContinue; if (Get-Module NetAdapter) { "LOADED:" + ((Get-Module NetAdapter).ExportedCommands.Keys | Where-Object {$_ -like '*Binding*'} | Sort-Object) -join "," } else { "MODULE_NOT_LOADED" }`)
	log.Printf("bridge: NetAdapter binding cmdlets available: %s", strings.TrimSpace(diagOut))

	script := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
Import-Module NetAdapter -Force
if (Get-Command Add-NetAdapterBinding -ErrorAction SilentlyContinue) {
    Add-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
    Add-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
}
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

// powershell runs a PowerShell script passed via stdin.
// Using stdin (-Command -) avoids command-line length limits and quoting
// issues that arise when embedding multi-line scripts as -Command arguments.
func powershell(script string) (string, error) {
	cmd := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-",
	)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// psSingleQuote wraps s in PowerShell single quotes, escaping any embedded
// single quotes by doubling them. Single-quoted strings are literal in
// PowerShell — wildcards like * are not expanded.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
