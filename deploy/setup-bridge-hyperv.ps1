# setup-bridge-hyperv.ps1
#
# Method 2 — Hyper-V External Virtual Switch (Windows Pro / Enterprise / Education)
#
# Creates an External Hyper-V switch on the physical NIC, then bridges the
# supervpn TAP adapter with the resulting vEthernet adapter.  The Hyper-V switch
# part is fully automated; the final TAP bridge step is the same as Method 1.
#
# Requirements:
#   • Windows 10/11 Pro, Enterprise, or Education
#   • Hyper-V feature enabled:
#       Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
#   • tap-windows6 driver installed
#   • Administrator privileges
#
# Usage:
#   .\setup-bridge-hyperv.ps1 -PhysicalNIC "Ethernet"
#   .\setup-bridge-hyperv.ps1 -PhysicalNIC "Ethernet 2" -SwitchName "supervpn-bridge" -TapNIC "supervpn-tap"

param(
    [Parameter(Mandatory = $true)]
    [string]$PhysicalNIC,

    [string]$SwitchName = "supervpn-bridge",
    [string]$TapNIC     = "supervpn-tap"
)

#-- privilege check -----------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal]
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

#-- check Hyper-V -------------------------------------------------------------
$hvFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
if (-not $hvFeature -or $hvFeature.State -ne "Enabled") {
    Write-Error @"
Hyper-V is not enabled on this machine.
Enable it with:
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -Restart
Then re-run this script.
Alternatively use setup-bridge-netbridge.ps1 (works on all Windows editions).
"@
    exit 1
}

#-- verify physical NIC -------------------------------------------------------
$phys = Get-NetAdapter -Name $PhysicalNIC -ErrorAction SilentlyContinue
if (-not $phys) {
    Write-Error "Adapter '$PhysicalNIC' not found."
    Get-NetAdapter | Select-Object Name, InterfaceDescription | Format-Table
    exit 1
}

#-- Step 1: create Hyper-V External Switch ------------------------------------
Write-Host "Step 1: Creating Hyper-V External Switch '$SwitchName' on '$PhysicalNIC'..."

$sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if ($sw) {
    Write-Host "  Switch '$SwitchName' already exists — skipping creation."
} else {
    New-VMSwitch -Name $SwitchName `
                 -NetAdapterName $PhysicalNIC `
                 -AllowManagementOS $true `
                 -ErrorAction Stop
    Write-Host "  Switch '$SwitchName' created."
}

# The switch creates a "vEthernet (SwitchName)" management OS adapter.
$vEthName = "vEthernet ($SwitchName)"
Write-Host "  Management OS adapter: '$vEthName'"

# Wait for the vEthernet adapter to appear.
$deadline = (Get-Date).AddSeconds(30)
while (-not (Get-NetAdapter -Name $vEthName -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) {
        Write-Error "Timed out waiting for '$vEthName' to appear."
        exit 1
    }
    Start-Sleep -Milliseconds 500
}
Write-Host "  '$vEthName' is ready."

#-- Step 2: bridge vEthernet + TAP (same as netbridge method) -----------------
Write-Host ""
Write-Host "Step 2: Bridge '$vEthName' with TAP adapter '$TapNIC'..."

$tap = Get-NetAdapter -Name $TapNIC -ErrorAction SilentlyContinue
if (-not $tap) {
    Write-Error "TAP adapter '$TapNIC' not found. Is tap-windows6 installed?"
    exit 1
}

$existing = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Network Bridge" }
if ($existing) {
    Write-Host "  Windows Network Bridge already exists: $($existing.Name) — manual check recommended."
} else {
    Write-Host ""
    Write-Host "  Hyper-V switch is running. Now add '$TapNIC' to the bridge with '$vEthName':"
    Write-Host ""
    Write-Host "  1. Win+R → ncpa.cpl"
    Write-Host "  2. Hold Ctrl, click '$vEthName' and '$TapNIC'"
    Write-Host "  3. Right-click → 'Bridge Connections'"
    Write-Host ""
    Write-Host "  Data flow after setup:"
    Write-Host "    Physical NIC ←→ Hyper-V Switch ←→ vEthernet ←→ NetBridge ←→ TAP ←→ supervpn ←→ Hub"
}

Write-Host ""
Write-Host "============================================================"
Write-Host " Hyper-V External Switch setup complete."
Write-Host " Complete Step 2 above, then start supervpn-client."
Write-Host "============================================================"
