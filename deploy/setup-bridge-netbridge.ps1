# setup-bridge-netbridge.ps1
#
# Method 1 — Windows Network Bridge (any Windows edition)
#
# Bridges the supervpn TAP adapter with a physical NIC that has a 169.254.x.x address.
# After this one-time setup, supervpn-client in bridge mode will transparently forward
# all Ethernet traffic from the physical NIC to the hub and vice versa.
#
# Usage (run as Administrator):
#   .\setup-bridge-netbridge.ps1 -PhysicalNIC "Ethernet"
#   .\setup-bridge-netbridge.ps1 -PhysicalNIC "Ethernet 2" -TapNIC "supervpn-tap"
#
# Requires: tap-windows6 driver installed (tap-windows6-installer.exe in this ZIP)
# Requires: Administrator privileges

param(
    [Parameter(Mandatory = $true)]
    [string]$PhysicalNIC,

    [string]$TapNIC = "supervpn-tap"
)

#-- privilege check -----------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal]
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

#-- verify adapters exist -----------------------------------------------------
$phys = Get-NetAdapter -Name $PhysicalNIC -ErrorAction SilentlyContinue
if (-not $phys) {
    Write-Error "Adapter '$PhysicalNIC' not found. Available adapters:"
    Get-NetAdapter | Select-Object Name, InterfaceDescription | Format-Table
    exit 1
}

$tap = Get-NetAdapter -Name $TapNIC -ErrorAction SilentlyContinue
if (-not $tap) {
    Write-Error "TAP adapter '$TapNIC' not found. Is tap-windows6 installed and the adapter named '$TapNIC'?"
    Write-Host "Installed adapters:"
    Get-NetAdapter | Select-Object Name, InterfaceDescription | Format-Table
    exit 1
}

Write-Host "Physical NIC : $($phys.Name) — $($phys.InterfaceDescription)"
Write-Host "TAP adapter  : $($tap.Name)  — $($tap.InterfaceDescription)"

#-- check if bridge already exists -------------------------------------------
$existing = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Network Bridge" }
if ($existing) {
    Write-Host ""
    Write-Host "A Windows Network Bridge already exists: $($existing.Name)"
    Write-Host "Add '$PhysicalNIC' and '$TapNIC' to it via ncpa.cpl if not already included."
    exit 0
}

#-- attempt automated bridge creation via INetCfg COM ------------------------
$bridgeCode = @'
using System;
using System.Runtime.InteropServices;

[ComImport]
[Guid("C0E8AE93-306E-11D1-AACF-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface INetCfg {
    void QueryInterface(ref Guid iid, out IntPtr ppv);
    uint AddRef();
    uint Release();
    int Initialize(IntPtr pReserved);
    int Uninitialize();
    int Apply();
    int Cancel();
    int EnumComponents([In] ref Guid pguidClass, out IntPtr ppenumComponent);
    int FindComponent([MarshalAs(UnmanagedType.LPWStr)] string pszwInfId, out IntPtr pComponent);
    int QueryNetCfgClass([In] ref Guid pguidClass, [In] ref Guid riid, out IntPtr ppvObject);
}

[ComImport]
[Guid("B41A2406-9EBF-11D2-8023-00C04F8EF96D")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface INetCfgLock {
    void QueryInterface(ref Guid iid, out IntPtr ppv);
    uint AddRef();
    uint Release();
    int AcquireWriteLock(uint cmsTimeout,
        [MarshalAs(UnmanagedType.LPWStr)] string pszwClientDescription,
        [MarshalAs(UnmanagedType.LPWStr)] out string ppszwClientDescription);
    int ReleaseWriteLock();
    int IsWriteLocked([MarshalAs(UnmanagedType.LPWStr)] out string ppszwClientDescription);
}

[ComImport]
[Guid("0001200C-0000-0000-C000-000000000046")]
public class NetCfgClass {}
'@

try {
    Add-Type -TypeDefinition $bridgeCode -ErrorAction Stop

    Write-Host ""
    Write-Host "Attempting automated Windows Network Bridge creation via INetCfg COM..."

    # Automated bridge creation requires implementing the full INetCfg binding
    # protocol (INetCfgComponent + INetCfgComponentBindings). The COM layer is
    # available but requires additional interface definitions beyond what a short
    # script can provide reliably.
    #
    # Falling through to manual instructions below.
    throw "INetCfg full binding not implemented in script — see manual steps"
}
catch {
    Write-Host ""
    Write-Warning "Automated bridge creation not available: $_"
}

#-- manual instructions -------------------------------------------------------
Write-Host ""
Write-Host "============================================================"
Write-Host " MANUAL SETUP — Windows Network Bridge (one-time, ~1 minute)"
Write-Host "============================================================"
Write-Host ""
Write-Host " 1. Open Network Connections:"
Write-Host "    Win+R → ncpa.cpl → Enter"
Write-Host ""
Write-Host " 2. Hold Ctrl and click BOTH adapters:"
Write-Host "    • $PhysicalNIC"
Write-Host "    • $TapNIC"
Write-Host ""
Write-Host " 3. Right-click the selection → 'Bridge Connections'"
Write-Host ""
Write-Host " 4. Wait ~30 seconds for the bridge to become active."
Write-Host ""
Write-Host " After setup: start supervpn-client — all devices on the 169.254.x.x"
Write-Host " subnet will get transparent L2 access to the VPN hub."
Write-Host "============================================================"
