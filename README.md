# supervpn

Custom L2 VPN with automatic packet-loss recovery (FEC) and TLS/TCP fallback.

Four binaries: **server** (Linux), **CLI client**, and **GUI client** (Windows/macOS).

## Download

Latest release: [atlanteg/supervpn-releases](https://github.com/atlanteg/supervpn-releases/releases/latest)

| File | Platform | Description |
|---|---|---|
| `supervpn-server` | Linux amd64 | Server |
| `supervpn-client-windows-amd64.exe` | Windows amd64 | CLI client |
| `supervpn-client-darwin-arm64` | macOS Apple Silicon | CLI client |
| `supervpn-client-darwin-amd64` | macOS Intel | CLI client |
| `supervpn-client-gui-windows-amd64.exe` | Windows amd64 | GUI client (Win32/GDI — works on RDP, Hyper-V, no GPU needed) |
| `superVPN-macos.zip` | macOS universal | GUI client (.app bundle, arm64 + amd64) |

---

## Overview

supervpn is a custom L2 VPN system. It combines the roles of SoftEther VPN Bridge and Client into a single client binary, paired with a multi-hub L2 server.

**Server (Linux):** Runs N independent Hubs. Each Hub is a transparent L2 broadcast domain — it switches Ethernet frames between connected clients exactly like a network switch.

**Client (Windows/macOS/Linux):** Two operating modes:

- **Bridge mode** — detects a network interface with a `169.254.0.0/16` (APIPA) address and transparently forwards all L2 traffic to the hub. No manual routes needed. Frame capture method per platform:

  | Platform | Method | Notes |
  |---|---|---|
  | Windows | Npcap (primary) | `promisc=1`; NDIS-loopback suppression for injected frames |
  | Windows | NDISUIO (fallback) | `OID_GEN_CURRENT_PACKET_FILTER = PROMISCUOUS` |
  | Windows | tap + Windows Bridge (fallback) | Bridge sets promiscuous automatically |
  | macOS | BPF | `BIOCPROMISC` + `BIOCSSEESENT=0` |
  | Linux | kernel TAP | Bridge sets promiscuous automatically |

- **Direct mode** — if no 169.254 interface is found, opens a TAP/WinTun adapter (`supervpn-tap`, L2, full Ethernet frames). Participates in the hub's L2 domain alongside bridge clients — ARP, unicast, and broadcast work transparently. Assign an IP after connecting:
  ```
  netsh interface ip set address "supervpn-tap" static 192.168.5.1 255.255.255.0
  ```

  On Windows, direct mode tries **WinTun** first (L2 emulation via ring-buffer, bypasses NDIS LWF filters used by FortiClient/OpenVPN), then falls back to tap-windows6.

**Transport:**
- **UDP** (primary) with Reed-Solomon FEC (SMPTE 2022-1 style). For every K data packets, R repair packets are added; any ≤ R losses in a block are recovered without retransmit.
- **TCP/TLS 1.3** (fallback) for restrictive firewalls and ТСПУ. The client probes UDP every 5 minutes and switches back automatically.
- **Dual-path** — two parallel connections (port N and N+1) for both protocols. Data and repair symbols are duplicated across both paths. The FEC decoder deduplicates via a `done` flag — no duplicates at the application layer.

**Authentication:** Login + password. The wire sends `hex(SHA-256(password))`; the server stores `bcrypt(wire_hash)`.

**Encryption:** AES-128-GCM. Per-session random 4-byte salt + counter-based 8-byte nonce. Replay window: 512 packets.

**Key derivation:** HKDF-SHA256 from `SHA-256(password) + hub_name + login`. Unique per (user, hub) pair.

---

## Architecture / Key design decisions

| Topic | Decision | Reason |
|---|---|---|
| Transport | UDP primary + TCP/TLS fallback | FEC requires UDP; TCP fallback for restrictive firewalls/ТСПУ |
| Encryption | AES-128-GCM | Speed over strength. Works through ТСПУ. |
| FEC | Reed-Solomon/XOR matrix (SMPTE 2022-1 style) | Recovers from ≤5% random packet loss without retransmit |
| FEC negotiation | Server advertises K/R in AuthOK (2 extra bytes) | Client auto-adopts server params; no manual config alignment needed |
| Authentication | Login + password (bcrypt stored, SHA-256 wire) | Simple, no PKI required |
| Server language | Go | Fast development, excellent networking, single binary deploy |
| Client language | Go | Same codebase, cross-compile to Windows/macOS |
| Windows capture | WinTun (WireGuard driver) | Signed, modern, no NDIS complexity |

---

## Repository structure

```
cmd/
  supervpn-server/     — server entrypoint
  supervpn-client/     — CLI client entrypoint
  supervpn-client-gui/ — GUI client entrypoint (Walk/Win32 on Windows, Fyne on macOS)
internal/
  crypto/              — AES-128-GCM, ReplayWindow (verbatim from myvpn — do not modify)
  proto/               — wire frame format
  fec/                 — Forward Error Correction (Reed-Solomon/XOR)
  transport/           — UDP + TCP transport abstraction
  hub/                 — server L2 hub / MAC table / forwarding
  bridge/              — client 169.254 detection + L2 bridge logic
  auth/                — login/password auth
  config/              — TOML config structures
  update/              — auto-update: GitHub API + mirrors, FetchAsset
  vpnclient/           — shared VPN engine (Client struct, reconnect loop, statistics)
  clientadapter/       — platform-specific adapter selection (bridge/direct/WinTun)
pkg/
  tun/                 — TAP (Linux/Windows tap0901), WinTun L2 emulation (Windows),
                         BPF (macOS bridge), utun (macOS direct)
dist/
  linux/               — server + configs + systemd unit
  windows/             — client + tap-driver + wintun.dll + configs
  macos/               — client (arm64 + amd64) + configs
```

---

## Quick start

### 1. Server (Linux)

Generate a bcrypt hash for a user's password:

```bash
./supervpn-server hashpw mypassword
# $2a$10$...
```

Config at `/etc/supervpn/server.toml`:

```toml
listen        = "0.0.0.0:5555"
listen_tcp    = "0.0.0.0:443"
status_listen = "127.0.0.1:9090"   # admin API — loopback only
update_listen = "0.0.0.0:80"       # client update mirror

[fec]
k = 20
r = 6

[[hub]]
id   = 1
name = "office"

  [[hub.user]]
  login         = "alice"
  password_hash = "$2a$10$..."   # supervpn-server hashpw alice

  [[hub.user]]
  login         = "bob"
  password_hash = "$2a$10$..."
```

Run:

```bash
./supervpn-server -config /etc/supervpn/server.toml
```

On startup the server downloads client binaries to `dist/` and serves them as an update mirror on port 80.

Open firewall ports:

```bash
ufw allow 5555/udp   # VPN UDP primary
ufw allow 5556/udp   # VPN UDP secondary (dual-path)
ufw allow 443/tcp    # VPN TLS primary
ufw allow 444/tcp    # VPN TLS secondary (dual-path)
ufw allow 80/tcp     # update mirror for clients
# 9090/tcp — admin API, loopback only — do not expose externally
```

### 2. CLI client

Config `client.toml`:

```toml
server        = "vpn.example.com:5555"
server_tcp    = "vpn.example.com:443"
status_listen = "127.0.0.1:9191"
hub_id        = 1
login         = "alice"
password      = "mypassword"

# transport = "auto"   # auto (default) | udp | tcp
# mode      = "auto"   # auto (default) | direct | bridge

[tls]
sni = "microsoft.com"   # SNI in TLS ClientHello (optional)
```

The `[fec]` section is optional. Since v2, the server advertises its K/R in the AuthOK message — the client adopts the server's parameters automatically without any manual alignment.

Run:

```bash
# Windows
supervpn-client.exe -config client.toml

# macOS — remove quarantine and make executable first
xattr -d com.apple.quarantine supervpn-client-darwin-arm64
chmod +x supervpn-client-darwin-arm64
sudo ./supervpn-client-darwin-arm64 -config client.toml   # bridge mode requires root

# Without a config file — pass everything as flags
supervpn-client -server vpn.example.com:5555 -login alice -password mypassword

# Force TLS (skip UDP probing)
supervpn-client -config client.toml -transport tcp

# Force direct mode (skip bridge detection)
supervpn-client -config client.toml -mode direct
```

On startup the client kills any stale previous instance (via a PID file), then checks for updates and restarts if a newer version is found.

Sample log output:

```
bridge mode: bridging local NIC "Ethernet" (addr=169.254.3.7 mac=84:a6:c8:d1:06:bf) → "supervpn-tap"
session 469949699 active via udp
keepalive: ping #4 sent, last pong 9s ago | FEC data=1247 repair=62 recovered=3 lost=0 | ↑12.4 KB/s ↓8.1 KB/s
```

`FEC recovered` — packets lost in transit and recovered from repair symbols without retransmit.
`FEC lost` — blocks with more losses than R (unrecoverable); should be 0 under normal conditions.

### 3. GUI client — Windows

1. Download `supervpn-client-gui-windows-amd64.exe` from the [releases page](https://github.com/atlanteg/supervpn-releases/releases/latest).
2. Run it — the window opens without a console.
3. If Windows SmartScreen blocks it, click "More info" → "Run anyway".

Pure Win32/GDI, no OpenGL. Works on RDP, Hyper-V, and any VM without a GPU. The TAP driver is embedded in the executable and auto-installed on first use via `pnputil` (requires Administrator).

### 4. GUI client — macOS

1. Download `superVPN-macos.zip` from the [releases page](https://github.com/atlanteg/supervpn-releases/releases/latest).
2. Unzip — you get `superVPN.app`.
3. Remove Gatekeeper quarantine (required, otherwise macOS blocks the app):
   ```bash
   xattr -d com.apple.quarantine superVPN.app
   ```
4. Move `superVPN.app` to `/Applications`.

The app is universal (arm64 + amd64) and works on both Apple Silicon and Intel.

macOS requires root for VPN adapter creation. Launch from Terminal:

```bash
sudo /Applications/superVPN.app/Contents/MacOS/superVPN
```

For convenience, add an alias to `~/.zshrc`:

```bash
alias supervpn='sudo /Applications/superVPN.app/Contents/MacOS/superVPN'
```

> Double-clicking the `.app` without sudo will open the window but connection will fail with `operation not permitted`. This is a macOS restriction that cannot be bypassed without an Apple Developer signature.

---

## GUI features

- **Config file dropdown** — auto-discovers all `.toml` files from the executable directory, `UserConfigDir/superVPN/`, and the home directory. Select one to load it instantly.
- **Auto-save on connect** — the current settings are saved to the config file on each successful connection.
- **Auto-connect on startup** — `auto_connect = true` in the config (Advanced → Behavior checkbox) makes the GUI connect automatically without pressing Connect.
- **Live stats on the Connection tab** — bytes/s up and down, FEC counters, connection state.
- **Status dot indicator** — color-coded circle in the window header: grey = disconnected, yellow = connecting, green = connected, red = error/reconnecting.
- **Minimize to tray** — `minimize_to_tray = true` (Advanced → Behavior) hides the window to the system tray on close/minimize; left-click the tray icon to restore.
- **Predefined server list** — a dropdown of named servers with aliases, editable from the config file.
- **Npcap button** — shows `Npcap ✓` (greyed out) when installed, or `Install Npcap` (active) when missing. Clicking launches the bundled Npcap installer.
- **TAP driver auto-install** — the tap-windows6 driver is embedded in the Windows executable and installed automatically on first use via `pnputil`. Requires Administrator.
- **WinTun** — embedded in the executable, extracted to `%LOCALAPPDATA%\superVPN\` on first use (not placed next to the exe).
- **Adapter mode in status bar** — shows whether the session is using bridge or direct mode.

---

## FEC parameters

FEC uses Reed-Solomon over GF(2⁸). The parameters are:

| Parameter | TOML key | Default | Meaning |
|---|---|---|---|
| K | `fec.k` | 20 | Data packets per FEC block |
| R | `fec.r` | 6 | Repair packets per FEC block |
| RepairDelay | `fec.repair_delay` | 500 | Milliseconds to delay repair packets after data |

Any ≤ R losses in a block are recovered without retransmit. Streaming delivery: packets before a gap are returned immediately without waiting for the full block.

**FEC negotiation (v2+):** The server advertises its active K and R in the AuthOK message (2 extra bytes after the session ID). The client automatically adopts the server's parameters. There is no need to manually align `fec.k`/`fec.r` in the client config. If the server sends K=0/R=0 (legacy), the client uses its own configured values.

---

## Configuration reference

### Server (`server.toml`)

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | string | — | UDP listen address, e.g. `0.0.0.0:5555` |
| `listen_tcp` | string | — | TLS/TCP listen address, e.g. `0.0.0.0:443` |
| `status_listen` | string | — | HTTP admin API, e.g. `127.0.0.1:9090` |
| `update_listen` | string | — | Update mirror for clients, e.g. `0.0.0.0:80`; if empty, served on `status_listen` |
| `update_dir` | string | `dist/` next to binary | Directory with client binaries for the mirror |
| `fec.k` | int | 20 | Data packets per FEC block |
| `fec.r` | int | 6 | Repair packets per FEC block |
| `tls.cert_file` | string | — | PEM cert (empty = auto self-signed) |
| `tls.key_file` | string | — | PEM key |
| `[[hub]]` | — | — | Hub section (multiple allowed) |
| `hub.id` | uint16 | — | Unique hub ID |
| `hub.name` | string | — | Hub name |
| `[[hub.user]]` | — | — | Hub user |
| `hub.user.login` | string | — | Login |
| `hub.user.password_hash` | string | — | bcrypt hash (generate with `supervpn-server hashpw`) |

### Client (`client.toml`)

| Key | Type | Default | Description |
|---|---|---|---|
| `server` | string | — | Server UDP address |
| `server_tcp` | string | `host:443` | Server TLS/TCP address (derived from `server` if not set) |
| `hub_id` | uint16 | 1 | Hub ID |
| `login` | string | — | Login |
| `password` | string | — | Password |
| `transport` | string | `auto` | `auto` / `udp` / `tcp` |
| `mode` | string | `auto` | `auto` — bridge if 169.254 found, else direct; `direct` — always direct TUN; `bridge` — force bridge (error if no 169.254) |
| `tun_name` | string | `supervpn` | TUN name in direct mode (macOS/Linux; ignored on Windows) |
| `bridge.tap_name` | string | `supervpn-tap` | TAP adapter name (bridge and direct mode on Windows) |
| `bridge.nic` | string | — | Physical NIC for bridge mode (empty = auto-detect by 169.254.x.x; adapters with `*` in name are skipped) |
| `bridge.setup_method` | string | `netbridge` | `netbridge` — Windows Network Bridge; `hyperv` — Hyper-V External Switch |
| `status_listen` | string | — | HTTP status API for the client |
| `update_mirrors` | []string | auto from `server` | Fallback mirrors; if empty, `http://server_host/update` (port 80) |
| `fec.k` | int | 20 | Data packets per block (overridden by server's advertised value at connect time) |
| `fec.r` | int | 6 | Repair packets per block (overridden by server's advertised value at connect time) |
| `fec.repair_delay` | int | 500 | Repair packet delay in milliseconds |
| `tls.sni` | string | server hostname | SNI in TLS ClientHello |
| `udp.knock_count` | int | 3 | Knock packets before auth |
| `udp.knock_size` | int | 16 | Knock packet size (bytes) |
| `udp.attempts` | int | 3 | UDP auth attempts before TLS fallback |
| `minimize_to_tray` | bool | false | Hide window to system tray on close/minimize (GUI only) |
| `auto_connect` | bool | false | Connect automatically on GUI startup (GUI only) |

**CLI flags** override the config file — all parameters are available as both `.toml` keys and command-line flags:

```
-config            path to .toml
-server            UDP address (host:port)
-server-tcp        TCP address (host:port)
-hub               hub ID
-login             login
-password          password
-transport         auto | udp | tcp
-mode              auto | direct | bridge
-tun-name          TUN name (direct mode, macOS/Linux)
-status-listen     HTTP status API address
-timeout           session timeout (e.g. 30s)
-update-mirrors    update mirrors (comma-separated)
-fec-k             FEC data packets per block
-fec-r             FEC repair packets per block
-fec-delay         repair frame delay (ms)
-tls-sni           SNI in TLS ClientHello
-udp-knock-count   knock packets before auth
-udp-knock-size    knock packet size (bytes)
-udp-attempts      UDP attempts before TLS fallback
-bridge-nic        physical NIC for bridge (Windows)
-bridge-tap        TAP adapter (Windows bridge/direct)
-bridge-method     netbridge | hyperv
```

---

## HTTP status API

### `GET http://127.0.0.1:9090/status` (server)

```json
{
  "version": "b122",
  "uptime": "2h15m30s",
  "udp_listen": "0.0.0.0:5555",
  "udp_listen_2": "0.0.0.0:5556",
  "tcp_listen": "0.0.0.0:443",
  "tcp_listen_2": "0.0.0.0:444",
  "hubs": [
    {
      "id": 1,
      "name": "office",
      "clients": [
        {
          "session_id": 3141592653,
          "login": "alice",
          "remote_addr": "1.2.3.4:51234",
          "secondary_addr": "1.2.3.4:51235",
          "mode": "udp",
          "connected_at": "2026-05-16T10:00:00Z",
          "duration": "2h14m58s",
          "frames_rx": 1024,
          "frames_tx": 980
        }
      ],
      "mac_table": [
        {
          "mac": "00:ff:ee:71:d2:3c",
          "ip": "192.168.5.1",
          "login": "alice",
          "session_id": 3141592653,
          "expires_in": "4m32s"
        }
      ]
    }
  ]
}
```

### `GET http://127.0.0.1:9191/status` (client)

```json
{
  "version": "b122",
  "uptime": "45m10s",
  "state": "connected",
  "session": {
    "session_id": 3141592653,
    "server": "vpn.example.com:5555",
    "hub_id": 1,
    "login": "alice",
    "mode": "udp",
    "secondary_addr": "vpn.example.com:5556",
    "connected_at": "2026-05-16T11:30:00Z",
    "duration": "45m10s",
    "fec_data_rx": 1247,
    "fec_repair_rx": 62,
    "fec_recovered": 3,
    "fec_lost": 0,
    "bytes_tx": 12700,
    "bytes_rx": 8300
  }
}
```

`state`: `starting` | `connecting` | `connected` | `reconnecting`

### `POST /api/hubs/{hub_id}/kick/{session_id}` — kick session

Disconnects the session and **permanently bans the client's IP** address.
The login is also blocked for 5 minutes to prevent immediate reconnect.

```bash
curl -X POST http://127.0.0.1:9090/api/hubs/1/kick/3141592653
# {"status":"ok","session_id":3141592653,"login":"alice","banned_ip":"1.2.3.4"}
```

---

### IP ban

```bash
# Ban an IP (also kicks all active sessions from that IP)
curl -X POST http://127.0.0.1:9090/api/ips/1.2.3.4/ban
# {"status":"ok","action":"ban","ip":"1.2.3.4"}

# Unban
curl -X POST http://127.0.0.1:9090/api/ips/1.2.3.4/unban
# {"status":"ok","action":"unban","ip":"1.2.3.4","was_banned":true}

# List all banned IPs
curl http://127.0.0.1:9090/api/bans
# {"banned_ips":["1.2.3.4","5.6.7.8"]}
```

Bans survive server restarts (`banned_ips.json` next to the binary).

---

### Login ban (per hub)

Ban a specific login on a specific hub. The same login can remain allowed on other hubs.

```bash
# Ban login on hub 2 (also kicks active sessions)
curl -X POST http://127.0.0.1:9090/api/hubs/2/loginbans/alice
# {"status":"ok","action":"ban","login":"alice","hub_id":2}

# Unban
curl -X POST http://127.0.0.1:9090/api/hubs/2/loginunbans/alice
# {"status":"ok","action":"unban","login":"alice","hub_id":2,"was_banned":true}

# List banned logins on hub 2
curl http://127.0.0.1:9090/api/hubs/2/loginbans
# {"hub_id":2,"banned_logins":["alice","bob"]}
```

Bans survive server restarts (`banned_logins.json` next to the binary).
Active bans are also visible in `GET /status` under `banned_ips` and `banned_logins`.

---

## Auto-update

On startup every binary (server and all clients) checks for a newer release and restarts automatically if one is found.

**Sources (tried in order):**
1. GitHub releases (`api.github.com/repos/atlanteg/supervpn-releases/releases/latest`)
2. Built-in mirror list — all 5 known server IPs at `http://{ip}/update`

No configuration needed. If GitHub is unreachable, any of the 5 servers acts as a fallback mirror.
Additional mirrors can be added via `update_mirrors` in the client config (prepended before the built-in list).

**Server mirror:** each server downloads all client binaries + its own binary from GitHub into `dist/` on startup and serves them at `GET /update/{asset}`. This means servers can update each other even when GitHub is unreachable. `GET /update/` (trailing slash) returns an HTML listing.

---

## Build

**Prerequisites:** Go 1.24+. CGO is only required for the macOS Fyne GUI build.

```bash
# Server (Linux/amd64)
go build ./cmd/supervpn-server

# CLI client (native platform)
go build ./cmd/supervpn-client

# GUI client — Windows (Walk/Win32, no CGO)
GOOS=windows GOARCH=amd64 go build ./cmd/supervpn-client-gui

# GUI client — macOS (Fyne, requires CGO)
go build -tags fyne ./cmd/supervpn-client-gui
```

Cross-compile examples:

```bash
# Server
GOOS=linux GOARCH=amd64 go build -o supervpn-server ./cmd/supervpn-server

# CLI client for Windows
GOOS=windows GOARCH=amd64 go build -o supervpn-client.exe ./cmd/supervpn-client

# CLI client for macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o supervpn-client-arm64 ./cmd/supervpn-client

# GUI client for macOS (requires CGO)
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -tags fyne \
  -o supervpn-client-gui-arm64 ./cmd/supervpn-client-gui

# GUI client for Windows (Walk/Win32, no CGO)
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-H windowsgui" \
  -o supervpn-client-gui.exe ./cmd/supervpn-client-gui
```

Makefile targets:

```bash
make build               # all platforms → dist/
make server              # Linux server only
make client-windows      # Windows CLI client
make client-darwin-arm64 # macOS Apple Silicon CLI client
make client-darwin-amd64 # macOS Intel CLI client
make test                # go test -race ./...
make zip                 # build supervpn-dist.zip
```

The version (`b{N}`) is set automatically from the git commit count — no manual tagging required.

---

## CI / Releases

Every push to `main` triggers four parallel GitHub Actions jobs:

| Job | Runner | Output |
|---|---|---|
| `build-server-cli` | ubuntu-latest | `supervpn-server`, CLI clients for Windows/macOS (no CGO) |
| `build-gui-macos` | macos-latest | GUI clients for darwin/arm64 and darwin/amd64; `superVPN.app` universal bundle + zip |
| `build-gui-windows` | windows-latest | `supervpn-client-gui-windows-amd64.exe` (Walk/Win32, no CGO, TAP driver embedded) |

After all jobs pass, a `release` job publishes a new GitHub release (tagged `b{N}`) to [atlanteg/supervpn-releases](https://github.com/atlanteg/supervpn-releases). The release includes individual binaries and a `supervpn-dist.zip` with everything combined.

---

## Deploy (systemd)

```bash
install -o root -g root -m 755 supervpn-server /usr/local/bin/
install -d /etc/supervpn
install -m 640 server.toml /etc/supervpn/server.toml
cp dist/linux/supervpn-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now supervpn-server
```

---

## Security notes

- **Encryption:** AES-128-GCM. Each packet: `[peer_id:4][counter:8][nonce:12][ciphertext+tag]`.
- **Nonce:** `counter(8) || salt(4)`. The `salt` is 4 random bytes per session, ensuring nonce uniqueness even in the event of session ID collision.
- **Key:** HKDF-SHA256 from `SHA-256(password) + hub_name + login`. Unique per (user, hub) pair.
- **Wire auth:** `hex(SHA-256(password))` sent to the server; the server stores `bcrypt(wire_hash)`.
- **Replay protection:** sliding window of 512 packets.
- **Kick:** forcible disconnect via HTTP API; automatically bans the client's IP permanently and blocks the login for 5 minutes.
- **IP ban:** permanent ban by IP address, survives restarts (`banned_ips.json`). API: `POST /api/ips/{ip}/ban|unban`, `GET /api/bans`.
- **Login ban:** permanent ban by login per hub, survives restarts (`banned_logins.json`). API: `POST /api/hubs/{id}/loginbans|loginunbans/{login}`, `GET /api/hubs/{id}/loginbans`.
- **Management API:** no authentication — bind `status_listen` to loopback (`127.0.0.1`) only, never expose externally.

---

## License

Proprietary. All rights reserved.
