supervpn — macOS Client
=======================

Files:
  supervpn-client-arm64   — Apple Silicon (M1/M2/M3/M4)
  supervpn-client-amd64   — Intel Mac
  client.toml.example     — example config

First run: remove quarantine flag
----------------------------------
  xattr -d com.apple.quarantine supervpn-client-arm64   # or -amd64

Requirements
------------
  - macOS 12+ recommended
  - sudo / root (BPF and utun require elevated privileges)

Mode A — Direct (no 169.254.x.x address on your machine)
---------------------------------------------------------
  1. cp client.toml.example client.toml && nano client.toml
  2. sudo ./supervpn-client-arm64 -config client.toml
  3. A utun interface appears; assign an IP:
       sudo ifconfig utunX 10.0.0.2 10.0.0.1

Mode B — Bridge (your physical NIC has a 169.254.x.x address)
--------------------------------------------------------------
The client attaches directly to the physical NIC via BPF (/dev/bpf*).
No virtual adapter or extra setup required.

  1. Verify your NIC has a 169.254 address:
       ifconfig | grep 169.254
     If not, add one temporarily:
       sudo ifconfig en0 169.254.1.1 255.255.0.0 alias

  2. sudo ./supervpn-client-arm64 -config client.toml

  All Ethernet frames from that NIC are forwarded to the hub transparently.

Determine which binary to use
------------------------------
  uname -m
    arm64  → supervpn-client-arm64
    x86_64 → supervpn-client-amd64
