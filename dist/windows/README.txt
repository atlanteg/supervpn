supervpn — Windows Client
=========================

Files:
  supervpn-client.exe           — client binary (windows/amd64)
  wintun.dll                    — WinTun driver (L3 direct mode)
  tap-driver/                   — tap0901 driver files (L2 bridge mode)
  install-tap-driver.bat        — installs tap0901 driver (one-time)
  client.toml.example           — example config

Requirements
------------
  - Windows 10 / 11 (amd64)
  - Administrator rights (right-click cmd → "Run as Administrator")
  - wintun.dll must be in the same folder as supervpn-client.exe

Mode A — Direct (no 169.254.x.x interface on your machine)
-----------------------------------------------------------
No driver install needed.

  1. Edit client.toml.example → save as client.toml
  2. Run supervpn-client.exe as Administrator

A "supervpn" WinTun adapter appears in ncpa.cpl. Assign any IP address
inside the hub subnet to it to communicate with other hub clients.

Mode B — Bridge (you have a 169.254.x.x interface, e.g. Realtek NIC)
----------------------------------------------------------------------
Used when your physical NIC has a link-local (APIPA) address.
The client transparently forwards all Ethernet traffic to the hub —
no manual routing or IP configuration needed.

  Step 1: Install tap0901 driver (one time only)
    Right-click install-tap-driver.bat → Run as Administrator
    Reboot if prompted.

  Step 2: Run client
    Edit client.toml.example → save as client.toml
    Run supervpn-client.exe as Administrator

The client handles the rest automatically:
  - Renames the TAP adapter to "supervpn-tap" if needed
  - Creates the Windows Network Bridge between your physical NIC
    and supervpn-tap (same as ncpa.cpl → Bridge Connections)

Expected log output on first run:
  bridge: creating Windows Network Bridge ("Ethernet" <-> "supervpn-tap") ...
  bridge: Network Bridge "Network Bridge" ready
  bridge mode: bridging local NIC "Ethernet" (addr=169.254.x.x mac=...) -> "supervpn-tap"
  session XXXXXXXXX active via udp
  keepalive: ping #1 sent, last pong 0s ago | FEC data=0 repair=0 recovered=0 lost=0

If bridge creation fails, the client logs a warning and you can set it
up manually: ncpa.cpl → select both adapters → right-click → Bridge Connections.

Status API (if configured in client.toml):
  curl http://127.0.0.1:9191/status
