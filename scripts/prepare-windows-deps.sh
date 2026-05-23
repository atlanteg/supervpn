#!/usr/bin/env bash
# Replicates the CI "Download wintun.dll + tap-driver + Npcap" step for local builds.
# Run once before building Windows binaries when pkg/tun/{wintun-dll,tap-driver,npcap-installer}
# are empty (fresh clone or after "git clean").
#
# Usage: bash scripts/prepare-windows-deps.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "=== wintun.dll ==="
if [ -f "$ROOT/pkg/tun/wintun-dll/wintun.dll" ]; then
    echo "  already present, skipping"
else
    curl -fsSL "https://www.wintun.net/builds/wintun-0.14.1.zip" -o "$TMP/wintun.zip"
    unzip -q "$TMP/wintun.zip" "wintun/bin/amd64/wintun.dll" -d "$TMP/wintun-pkg"
    cp "$TMP/wintun-pkg/wintun/bin/amd64/wintun.dll" "$ROOT/pkg/tun/wintun-dll/wintun.dll"
    echo "  OK ($(wc -c < "$ROOT/pkg/tun/wintun-dll/wintun.dll") bytes)"
fi

echo "=== tap-windows6 driver (amd64) ==="
if [ -f "$ROOT/pkg/tun/tap-driver/tap0901.sys" ]; then
    echo "  already present, skipping"
else
    curl -fsSL "https://github.com/OpenVPN/tap-windows6/releases/download/9.27.0/dist.win10.zip" \
        -o "$TMP/tap-dist.zip"
    unzip -q "$TMP/tap-dist.zip" "dist.win10/amd64/*" -d "$TMP/tap-dist"
    cp "$TMP/tap-dist/dist.win10/amd64/OemVista.inf" "$ROOT/pkg/tun/tap-driver/"
    cp "$TMP/tap-dist/dist.win10/amd64/tap0901.sys"  "$ROOT/pkg/tun/tap-driver/"
    cp "$TMP/tap-dist/dist.win10/amd64/tap0901.cat"  "$ROOT/pkg/tun/tap-driver/"
    echo "  OK"
fi

echo "=== Npcap installer ==="
if compgen -G "$ROOT/pkg/tun/npcap-installer/*.exe" > /dev/null 2>&1; then
    echo "  already present, skipping"
else
    curl -fsSL "https://npcap.com/dist/npcap-1.88.exe" \
        -o "$ROOT/pkg/tun/npcap-installer/npcap-1.88.exe"
    echo "  OK ($(wc -c < "$ROOT/pkg/tun/npcap-installer/npcap-1.88.exe") bytes)"
fi

echo ""
echo "All deps ready. Now build with:"
echo "  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./cmd/supervpn-client-seema"
echo "  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./cmd/supervpn-client-gui"
