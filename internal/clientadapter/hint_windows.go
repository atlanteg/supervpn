//go:build windows

package clientadapter

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/atlanteg/supervpn/internal/config"
)

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

	psErr := bindMsBridge(physicalNIC, tapName)
	if psErr != nil {
		log.Printf("bridge: PowerShell ms_bridge bind failed: %v", psErr)
	}

	inetcfgErr := bindMsBridgeINetCfg(physicalNIC, tapName)
	if inetcfgErr != nil {
		log.Printf("bridge: INetCfg ms_bridge bind failed: %v", inetcfgErr)
	}

	if psErr != nil && inetcfgErr != nil {
		return fmt.Errorf("all bridge-creation methods failed (ps: %v; inetcfg: %v) — fallback: ncpa.cpl → select both adapters → Bridge Connections", psErr, inetcfgErr)
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

func isElevated() bool {
	out, err := powershell(`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "True"
}

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

func bindMsBridge(nic, tap string) error {
	diagOut, _ := powershell(`Import-Module NetAdapter -Force -ErrorAction SilentlyContinue; if (Get-Module NetAdapter) { "LOADED:" + ((Get-Module NetAdapter).ExportedCommands.Keys | Where-Object {$_ -like '*Binding*'} | Sort-Object) -join " " } else { "MODULE_NOT_LOADED" }`)
	log.Printf("bridge: NetAdapter binding cmdlets available: %s", strings.TrimSpace(diagOut))

	stateScript := fmt.Sprintf(`
Import-Module NetAdapter -Force -ErrorAction SilentlyContinue
$n = (Get-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue).Enabled
$t = (Get-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue).Enabled
"ms_bridge state: NIC=%s → $n  TAP=%s → $t"
`, psSingleQuote(nic), psSingleQuote(tap), nic, tap)
	stateOut, _ := powershell(stateScript)
	log.Printf("bridge: %s", strings.TrimSpace(stateOut))

	script := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
Import-Module NetAdapter -Force
if (Get-Command Add-NetAdapterBinding -ErrorAction SilentlyContinue) {
    Add-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
    Add-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
    Enable-NetAdapterBinding -Name %s -ComponentID ms_bridge
    Enable-NetAdapterBinding -Name %s -ComponentID ms_bridge
} elseif (Get-Command Enable-NetAdapterBinding -ErrorAction SilentlyContinue) {
    Enable-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
    Enable-NetAdapterBinding -Name %s -ComponentID ms_bridge -ErrorAction SilentlyContinue
    Set-NetAdapterBinding   -Name %s -ComponentID ms_bridge -Enabled $True -ErrorAction SilentlyContinue
    Set-NetAdapterBinding   -Name %s -ComponentID ms_bridge -Enabled $True -ErrorAction SilentlyContinue
} else {
    Write-Error "no NetAdapter binding cmdlets available"
}
`,
		psSingleQuote(nic), psSingleQuote(tap),
		psSingleQuote(nic), psSingleQuote(tap),
		psSingleQuote(nic), psSingleQuote(tap),
		psSingleQuote(nic), psSingleQuote(tap),
	)
	out, err := powershell(script)
	if err != nil {
		return fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(out))
	}

	stateOut2, _ := powershell(stateScript)
	log.Printf("bridge: after enable — %s", strings.TrimSpace(stateOut2))

	return nil
}

func bindMsBridgeINetCfg(nic, tap string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

[ComImport, Guid("C0E8AE93-306E-11D1-AACF-00805FC1270E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface INetCfg {
    [PreserveSig] int Initialize(IntPtr hwndParent);
    [PreserveSig] int Uninitialize();
    [PreserveSig] int Apply();
    [PreserveSig] int Cancel();
    [PreserveSig] int EnumComponents([In] ref Guid pguidClass, out IEnumNetCfgComponent ppenum);
    [PreserveSig] int FindComponent([MarshalAs(UnmanagedType.LPWStr)] string pszwInfId, out INetCfgComponent pComponent);
    [PreserveSig] int QueryNetCfgClass([In] ref Guid pguidClass, [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppvObject);
}

[ComImport, Guid("C0E8AE9F-306E-11D1-AACF-00805FC1270E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface INetCfgLock {
    [PreserveSig] int AcquireWriteLock(uint cmsTimeout, [MarshalAs(UnmanagedType.LPWStr)] string pszwClientDescription, [MarshalAs(UnmanagedType.LPWStr)] out string ppszwClientDescription);
    [PreserveSig] int ReleaseWriteLock();
    [PreserveSig] int IsWriteLocked([MarshalAs(UnmanagedType.LPWStr)] out string ppszwClientDescription);
}

[ComImport, Guid("C0E8AE99-306E-11D1-AACF-00805FC1270E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface INetCfgComponent {
    [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string ppszwDisplayName);
    [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string pszwDisplayName);
    [PreserveSig] int GetHelpText([MarshalAs(UnmanagedType.LPWStr)] out string ppszwHelpText);
    [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string ppszwId);
    [PreserveSig] int GetCharacteristics(out uint pdwCharacteristics);
    [PreserveSig] int GetInstanceGuid(out Guid pGuid);
    [PreserveSig] int GetPnpDevNodeId([MarshalAs(UnmanagedType.LPWStr)] out string ppszwDevNodeId);
    [PreserveSig] int GetClassGuid(out Guid pGuid);
    [PreserveSig] int GetBindName([MarshalAs(UnmanagedType.LPWStr)] out string ppszwBindName);
    [PreserveSig] int GetDeviceStatus(out uint puStatus);
    [PreserveSig] int OpenParamKey(out IntPtr phkey);
    [PreserveSig] int RaisePropertyUi(IntPtr hwndParent, uint dwFlags, [MarshalAs(UnmanagedType.Interface)] object pvReserved);
}

[ComImport, Guid("C0E8AE9B-306E-11D1-AACF-00805FC1270E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface INetCfgComponentBindings {
    [PreserveSig] int BindTo([MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem);
    [PreserveSig] int UnbindFrom([MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem);
    [PreserveSig] int SupportsBindingInterface(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszwInterfaceName);
    [PreserveSig] int IsBoundTo([MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem);
    [PreserveSig] int IsBindableTo([MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem);
    [PreserveSig] int EnumBindingPaths(uint dwFlags, out IntPtr ppIEnumNetCfgBindingPath);
    [PreserveSig] int MoveBefore([MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem1, [MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem2);
    [PreserveSig] int MoveAfter([MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem1, [MarshalAs(UnmanagedType.Interface)] INetCfgComponent pnccItem2);
}

[ComImport, Guid("C0E8AE90-306E-11D1-AACF-00805FC1270E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IEnumNetCfgComponent {
    [PreserveSig] int Next(uint celt, out INetCfgComponent rgelt, out uint pceltFetched);
    [PreserveSig] int Skip(uint celt);
    [PreserveSig] int Reset();
    [PreserveSig] int Clone(out IEnumNetCfgComponent ppenum);
}

[ComImport, Guid("5B035261-40F9-11D1-AAEC-00805FC1270E")]
class CNetCfg {}

public static class NetCfgBridge {
    static readonly Guid GUID_DEVCLASS_NET = new Guid("4D36E972-E325-11CE-BFC1-08002BE10318");
    const int S_OK = 0;
    const uint ERROR_ALREADY_EXISTS = 0x800700B7;

    static INetCfgComponent FindAdapter(INetCfg cfg, string friendlyName) {
        IEnumNetCfgComponent en;
        Guid cls = GUID_DEVCLASS_NET;
        int hr = cfg.EnumComponents(ref cls, out en);
        if (hr != S_OK) return null;
        INetCfgComponent comp;
        uint fetched;
        while (en.Next(1, out comp, out fetched) == S_OK && fetched == 1) {
            string name;
            comp.GetDisplayName(out name);
            if (string.Equals(name, friendlyName, StringComparison.OrdinalIgnoreCase))
                return comp;
        }
        return null;
    }

    public static string Run(string nicName, string tapName) {
        INetCfg cfg = (INetCfg)new CNetCfg();
        int hr = cfg.Initialize(IntPtr.Zero);
        if (hr != S_OK) return "Initialize failed: 0x" + hr.ToString("X8");

        INetCfgLock lk = cfg as INetCfgLock;
        if (lk == null) { cfg.Uninitialize(); return "INetCfgLock QI failed"; }

        string holder;
        hr = lk.AcquireWriteLock(5000, "supervpn-client", out holder);
        if ((uint)hr == 0x8004A020u) { cfg.Uninitialize(); return "NEED_REBOOT"; }
        if (hr != S_OK) { cfg.Uninitialize(); return "AcquireWriteLock failed (holder=" + (holder ?? "") + "): 0x" + hr.ToString("X8"); }

        try {
            INetCfgComponent bridge;
            hr = cfg.FindComponent("ms_bridge", out bridge);
            if (hr != S_OK) return "FindComponent ms_bridge failed: 0x" + hr.ToString("X8");

            INetCfgComponentBindings bindings = bridge as INetCfgComponentBindings;
            if (bindings == null) return "INetCfgComponentBindings QI failed";

            INetCfgComponent nicComp = FindAdapter(cfg, nicName);
            if (nicComp == null) return "adapter not found: " + nicName;

            INetCfgComponent tapComp = FindAdapter(cfg, tapName);
            if (tapComp == null) return "adapter not found: " + tapName;

            hr = bindings.BindTo(nicComp);
            if (hr != S_OK && (uint)hr != ERROR_ALREADY_EXISTS)
                return "BindTo(" + nicName + ") failed: 0x" + hr.ToString("X8");

            hr = bindings.BindTo(tapComp);
            if (hr != S_OK && (uint)hr != ERROR_ALREADY_EXISTS)
                return "BindTo(" + tapName + ") failed: 0x" + hr.ToString("X8");

            hr = cfg.Apply();
            if (hr != S_OK) return "Apply failed: 0x" + hr.ToString("X8");

            return "OK";
        } finally {
            lk.ReleaseWriteLock();
            cfg.Uninitialize();
        }
    }
}
'@ -Language CSharp

$result = [NetCfgBridge]::Run(%s, %s)
Write-Output $result
`, psSingleQuote(nic), psSingleQuote(tap))

	out, err := powershell(script)
	result := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("inetcfg: powershell error: %v: %s", err, result)
	}
	if result == "NEED_REBOOT" {
		return fmt.Errorf("inetcfg: Windows requires a reboot before the network bridge can be created — please reboot and restart supervpn-client")
	}
	if result != "OK" {
		return fmt.Errorf("inetcfg: %s", result)
	}
	return nil
}

func powershell(script string) (string, error) {
	cmd := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-",
	)
	hideWindow(cmd)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
