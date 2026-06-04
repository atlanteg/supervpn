//go:build windows

// WinTun integration — uses the official WireGuard WinTun driver.
// Driver DLL must be present: wintun.dll (ship with installer).
// See: https://wintun.net/
package tun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// adapterGUID derives a stable GUID from the adapter name so every connect
// reuses the SAME WinTun device instead of creating a new one each time.
// Passing nil to CreateAdapter generates a fresh GUID per call, which — because
// the friendly name "supervpn" lingers briefly in the registry after removal —
// makes Windows append an incrementing suffix (supervpn 2, 3, …) and leaves a
// trail of ghost adapters. A fixed GUID keeps it to one device with one name.
func adapterGUID(name string) *windows.GUID {
	h := sha256.Sum256([]byte("supervpn-wintun-v1:" + name))
	g := &windows.GUID{
		Data1: binary.LittleEndian.Uint32(h[0:4]),
		Data2: binary.LittleEndian.Uint16(h[4:6]),
		Data3: binary.LittleEndian.Uint16(h[6:8]),
	}
	copy(g.Data4[:], h[8:16])
	return g
}

type windowsTUN struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
}

// openPlatform creates or opens a WinTun adapter and returns an L2-emulated
// Framer (windowsTUNL2) suitable for connecting to the hub's Ethernet domain.
func openPlatform(name string) (*windowsTUNL2, error) {
	raw, err := openWinTUN(name)
	if err != nil {
		return nil, err
	}
	return newWindowsTUNL2(raw), nil
}

func openWinTUN(name string) (*windowsTUN, error) {
	if err := ensureWintunDLL(); err != nil {
		// Non-fatal: log and continue — the DLL may already be on the system.
		log.Printf("tun/windows: wintun.dll setup: %v", err)
	}
	// Reuse a stable GUID so reconnects reuse the same device (no "supervpn N"
	// name growth, no ghost-adapter accumulation in the registry/PnP).
	adapter, err := wintun.CreateAdapter(name, "supervpn", adapterGUID(name))
	if err != nil {
		adapter, err = wintun.OpenAdapter(name)
		if err != nil {
			return nil, fmt.Errorf("tun/windows: open adapter %q: %w", name, err)
		}
	}
	session, err := adapter.StartSession(0x800000) // 8 MiB ring
	if err != nil {
		return nil, fmt.Errorf("tun/windows: start session: %w", err)
	}
	return &windowsTUN{adapter: adapter, session: session, name: name}, nil
}

// readIPOnce attempts to receive one IP packet from WinTun.
// If no packet is available it waits up to 50 ms and returns nil, nil so the
// caller can check other channels (inject, ctx) before retrying.
func (t *windowsTUN) readIPOnce(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	pkt, err := t.session.ReceivePacket()
	if err != nil {
		evt := t.session.ReadWaitEvent()
		windows.WaitForSingleObject(windows.Handle(evt), 50)
		return nil, nil // poll timeout — no packet yet
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	t.session.ReleaseReceivePacket(pkt)
	return cp, nil
}

func (t *windowsTUN) writeIP(ip []byte) error {
	if len(ip) == 0 {
		return nil
	}
	pkt, err := t.session.AllocateSendPacket(len(ip))
	if err != nil {
		return fmt.Errorf("tun/windows: alloc send: %w", err)
	}
	copy(pkt, ip)
	t.session.SendPacket(pkt)
	return nil
}

func (t *windowsTUN) IfName() string { return t.name }

func (t *windowsTUN) Close() error {
	t.session.End()
	return t.adapter.Close()
}
