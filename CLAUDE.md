# supervpn — Project Context

## What this is

supervpn is a custom L2 VPN system combining the roles of SoftEther VPN Bridge + Client
into a single client binary, and a multi-hub L2 server.

**Server (Linux):** Runs N independent Hubs. Each Hub is a transparent L2 broadcast domain —
it switches Ethernet frames between connected clients exactly like a network switch.

**Client (Windows/macOS, Go):** Detects network interfaces with 169.254.0.0/16 (link-local /
APIPA) addressing and transparently bridges all L2 traffic to the server hub. The client
combines the bridge + client roles.

## Key design decisions

| Topic | Decision | Reason |
|---|---|---|
| Transport | UDP primary + TCP fallback | FEC requires UDP; TCP fallback for restrictive firewalls/ТСПУ |
| Encryption | AES-128-GCM from internal/crypto | Taken verbatim from myvpn. Speed over strength. Works through ТСПУ. |
| FEC | Reed-Solomon/XOR matrix (SMPTE 2022-1 style) | Recovers from ≤5% random packet loss without retransmit |
| FEC negotiation | Server advertises K/R in AuthOK (+2 bytes) | Client auto-adopts server params; no manual config alignment needed |
| Authentication | Login + password (bcrypt stored, SHA-256 wire) | Simple, no PKI required |
| Server language | Go | Fast development, excellent networking, single binary deploy |
| Client language | Go | Same codebase, cross-compile to Windows/macOS |
| Windows GUI | Walk (Win32/GDI default) + Fyne (-tags fyne) | Walk works on RDP/Hyper-V without GPU; Fyne for native look |
| Windows capture | WinTun (WireGuard driver) | Signed, modern, no NDIS complexity |
| TAP driver | Embedded in exe, auto-installed via pnputil | No external tools; pnputil built into Windows Vista+ |

## GitHub accounts & remotes

| Account | Visibility | Purpose | git remote |
|---|---|---|---|
| `atlanteg` | Public | Source code mirror + **release hosting** | `origin` |
| `atlantegsrb` | Private | CI/CD (GitHub Actions build & release) | `new-origin` |

- Source of truth: push every commit to **both** remotes.
  - `git push origin main` — always (public mirror, no CI)
  - `git push new-origin main` — triggers CI; **ask user before pushing here**
- CI builds at `atlantegsrb/supervpn` → artifacts copied **manually** to `atlanteg/supervpn-releases`.
- Release tags live in `atlanteg/supervpn-releases` (public). The update system reads from there.

### Known server IPs (update mirrors)

All 5 servers are hardcoded in `internal/update/update.go` → `knownServerIPs`:

```
81.27.241.25
185.108.16.16
212.48.224.5
162.55.48.218
49.13.4.85
```

Each server exposes `GET /update/version` and `GET /update/{asset}` on port 80.

### Update chain (all binaries)

```
GitHub (atlanteg/supervpn-releases) → 81.27.241.25 → 185.108.16.16 → 212.48.224.5 → 162.55.48.218 → 49.13.4.85
```

- GitHub API: `https://api.github.com/repos/atlanteg/supervpn-releases/releases/latest`
- Download base: `https://github.com/atlanteg/supervpn-releases/releases/download/{tag}/{asset}`
- All clients and **servers** follow the same fallback chain.
- Servers also host `supervpn-server` itself in their mirror dir (`dist/`) so peer servers can pull it.

### Release procedure

1. `git push new-origin main` — triggers CI at `atlantegsrb/supervpn`
2. Wait for CI to pass (`gh run watch ... --repo atlantegsrb/supervpn`)
3. Download artifacts: `gh run download {run_id} --repo atlantegsrb/supervpn --dir /tmp/svpn-artifacts`
4. Read version: `strings .../supervpn-server | grep -E '^b[0-9]+$'`
5. Publish release: `gh release create b{N} --repo atlanteg/supervpn-releases --title "b{N}" ...files...`
6. Assets to include in every release:
   - `supervpn-server` (linux/amd64)
   - `supervpn-client-windows-amd64.exe`
   - `supervpn-client-darwin-amd64` / `supervpn-client-darwin-arm64`
   - `supervpn-client-gui-windows-amd64.exe`
   - `supervpn-client-gui-darwin-amd64` / `supervpn-client-gui-darwin-arm64`
   - `supervpn-seema-windows-amd64.exe`
   - `supervpn-dist.zip`, `README-user.pdf`

## Repository structure

```
cmd/
  supervpn-server/        — server entrypoint
  supervpn-client/        — headless CLI client entrypoint
  supervpn-client-gui/    — GUI client (Walk/Win32 default; Fyne with -tags fyne)
  supervpn-client-seema/  — stripped pre-configured client for seema hub (Windows only)
internal/
  crypto/            — AES-128-GCM, ReplayWindow (verbatim from myvpn)
  proto/             — wire frame format
  fec/               — Forward Error Correction (Reed-Solomon/XOR)
  transport/         — UDP + TCP transport abstraction
  hub/               — server L2 hub / MAC table / forwarding
  bridge/            — client 169.254 detection + L2 bridge logic
  auth/              — login/password auth
  config/            — TOML config structures
  update/            — self-update logic (GitHub + mirror fallback)
pkg/
  tun/               — platform TAP/WinTun (linux, windows build tags)
```

## Rules for all agents

- **Never modify internal/crypto/** — it is taken verbatim from myvpn and must stay identical.
- After every commit: `git push origin main` (public mirror). **Never push to `new-origin` without asking the user** — it triggers CI and costs build minutes.
- No external dependencies except: `golang.org/x/crypto`, `golang.org/x/sys`,
  `golang.zx2c4.com/wintun`, `github.com/pelletier/go-toml` (or BurntSushi/toml).
- Do not add comments explaining WHAT the code does — only WHY when non-obvious.
- Server targets Linux amd64. Client targets Windows amd64 (macOS is secondary).
- FEC parameters K and R must be configurable at runtime, not compile-time constants.
- When adding a new release asset: add its name to **both** `clientAssets` in `cmd/supervpn-server/main.go` AND to the CI release upload step in `.github/workflows/ci.yml`.

## Agents

### architect
**Role:** Protocol and component interface design.
**Owns:** internal/proto, interfaces between packages, wire format decisions.
**Authority:** Final say on any change to packet format or inter-component API.
**Trigger:** Before implementing any new protocol feature or changing Frame layout.

### protocol-engineer
**Role:** FEC implementation and transport reliability.
**Owns:** internal/fec, internal/transport.
**Focus:** Correct Reed-Solomon implementation, UDP/TCP switching logic,
congestion-friendly behavior (no retransmit, only FEC).
**Trigger:** Any change to FEC parameters, transport layer, or packet loss handling.

### server-dev
**Role:** Linux server implementation.
**Owns:** cmd/supervpn-server, internal/hub, internal/auth (server side).
**Focus:** Hub manager (create/delete/list hubs), session lifecycle, MAC table,
L2 forwarding correctness, concurrent client handling.
**Trigger:** Hub logic, session management, server main loop.

### windows-client-dev
**Role:** Windows client implementation.
**Owns:** cmd/supervpn-client, pkg/tun/tun_windows.go, internal/bridge.
**Focus:** WinTun integration, 169.254.0.0/16 interface detection, bridge loop,
Windows service wrapper (sc.exe / golang.org/x/sys/windows/svc).
**Trigger:** Any Windows-specific code or bridge logic.

### security
**Role:** Security audit.
**Owns:** Nothing directly — reviews crypto, auth, replay window usage.
**Focus:** Ensure AES-128-GCM nonce uniqueness, replay protection correctness,
no credential leakage in logs, auth protocol soundness.
**Trigger:** Before any release cut, or when crypto/auth code changes.

### devops
**Role:** Build, CI, packaging.
**Owns:** .github/workflows/, Makefile, build scripts.
**Focus:** Cross-compile client for windows/amd64 from Linux CI,
build server for linux/amd64, GitHub Actions, release artifact naming.
**Trigger:** CI failures, new platform targets, release preparation.

### qa-engineer
**Role:** Testing and loss simulation.
**Owns:** *_test.go files across all packages.
**Focus:** Unit tests for FEC (inject artificial losses), integration tests
for hub forwarding, transport fallback tests, crypto round-trip tests.
**Trigger:** New features, bug fixes, pre-release validation.

## Development workflow

1. Branch: work on `main` for now (small team).
2. Every meaningful change: `git add`, `git commit`, `git push origin main`.
3. Commits must be atomic — one logical change per commit.
4. Build check before commit: `make build` (or `go build ./...`).
5. To release: push to `new-origin` (**ask user first**), then follow the Release procedure above.
6. After CI passes: download artifacts and publish to `atlanteg/supervpn-releases` manually (see Release procedure).
