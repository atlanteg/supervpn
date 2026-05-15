supervpn — Windows Client
=========================

Files:
  supervpn-client.exe           — client binary (windows/amd64)
  wintun.dll                    — WinTun driver (L3 direct mode)
  tap-driver/                   — tap0901 driver files (L2 bridge mode)
  install-tap-driver.bat        — installs tap0901, renames adapter to "supervpn-tap"
  client.toml.example           — example config
  setup-bridge-netbridge.ps1    — bridge setup (all Windows editions)
  setup-bridge-hyperv.ps1       — bridge setup via Hyper-V (Pro/Enterprise only)

Requirements
------------
  - Windows 10 / 11 (amd64)
  - Administrator rights
  - wintun.dll must be in the same folder as supervpn-client.exe

Mode A — Direct (no 169.254.x.x interface on your machine)
-----------------------------------------------------------
No driver install needed. Just:
  1. Edit client.toml.example → save as client.toml
  2. Run supervpn-client.exe as Administrator
  3. A "supervpn" WinTun adapter appears; assign an IP from the hub subnet.

Mode B — Bridge (you have a 169.254.x.x interface)
---------------------------------------------------
Used when your physical NIC has a link-local (APIPA) address — the client
transparently forwards all Ethernet traffic to the hub.

  Step 1: Install tap0901 driver (one time)
    Right-click install-tap-driver.bat → Run as Administrator
    (Or: right-click tap-driver\OemVista.inf → Install)

  Step 2: Bridge the TAP adapter with your physical NIC (one time)
    Option 1 — any Windows edition:
      Right-click setup-bridge-netbridge.ps1 → Run with PowerShell as Admin
      Follow the on-screen ncpa.cpl instructions.
    Option 2 — Windows Pro/Enterprise with Hyper-V:
      Right-click setup-bridge-hyperv.ps1 → Run with PowerShell as Admin
      Provide your physical NIC name: -PhysicalNIC "Ethernet"

  Step 3: Run client
    Edit client.toml.example → save as client.toml
    Run supervpn-client.exe as Administrator
